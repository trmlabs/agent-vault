package httpcatalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxAutomatedAuthResponse bounds a sign-in answer: tokens and a browser
// seed, a few kilobytes in practice.
const maxAutomatedAuthResponse = 256 << 10

// revokeBackoff is the wait before the one retry of a failed revocation.
var revokeBackoff = 500 * time.Millisecond

// automatedAuthLogin signs the test user in through TRM's automated-auth
// service, which drives the app's Universal Login with the entry's Auth0
// organization. The service key and the user's email and password come from
// Vault on each sign-in and are never cached here. The broker keeps the
// access token and the user's non-secret claims. It revokes the refresh
// token the service also returns and keeps it nowhere: the request and
// response buffers are zeroed and the connection is closed. The request is
// never redirected, and the service's error answer, which can name the user,
// is neither logged nor passed on.
func (a *Auth0Tokens) automatedAuthLogin(ctx context.Context, e *Entry) (BrowserToken, error) {
	b := e.BrowserSession
	s := b.AutomatedAuth
	if a.AutomatedAuth == nil || s == nil || s.OrgID == "" {
		return BrowserToken{}, ErrBrowserLogin
	}
	values := map[string]string{}
	for name, ref := range map[string]KeyRef{
		"privateKey": s.Key.Field("private_key"), "email": b.User.Field("email"), "password": b.User.Field("password"),
	} {
		secret, err := a.Keys.Get(ctx, ref)
		if err != nil || secret.Value() == "" {
			return BrowserToken{}, ErrBrowserLogin
		}
		values[name] = secret.Value()
	}
	body, _ := json.Marshal(map[string]string{
		"privateKey": values["privateKey"], "profile": s.Profile, "orgId": s.OrgID,
		"email": values["email"], "password": values["password"],
	})
	defer clear(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+"/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	req.Header.Set("Content-Type", "application/json")
	// An idle connection would keep the answer, refresh token included, in
	// its read buffer. Sign-ins are minutes apart, so none is kept.
	req.Close = true
	client := *a.AutomatedAuth
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	issued := a.now()
	resp, err := client.Do(req)
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, maxAutomatedAuthResponse+1)
	defer clear(buf)
	n, err := io.ReadFull(resp.Body, buf)
	if (err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF)) || n > maxAutomatedAuthResponse ||
		resp.StatusCode != http.StatusOK {
		return BrowserToken{}, ErrBrowserLogin
	}
	// Only top-level fields are read. The browser seed the service also
	// returns repeats both tokens and is never parsed.
	var out struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		IDToken      string `json:"idToken"`
		ExpiresAt    string `json:"expiresAt"`
	}
	err = json.Unmarshal(buf[:n], &out)
	if out.RefreshToken != "" {
		a.revoke(ctx, e, out.RefreshToken)
		out.RefreshToken = ""
	}
	if err != nil || out.AccessToken == "" {
		return BrowserToken{}, ErrBrowserLogin
	}
	access, err := accessTokenClaims(out.AccessToken)
	// The access token is what the API checks, so it must carry the entry's
	// organization and audience; a token for any other is refused.
	if err != nil || access.Sub == "" || access.OrgID != s.OrgID || !access.hasAudience(b.Auth0.Audience) || access.Exp <= 0 {
		return BrowserToken{}, ErrBrowserLogin
	}
	expires := time.Unix(access.Exp, 0)
	if t, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil && t.Before(expires) {
		expires = t
	}
	life := expires.Sub(issued)
	if life < 2*time.Minute {
		return BrowserToken{}, ErrBrowserLogin
	}
	// The seed's ID token needs sub and org_id, which the app reads. They
	// come from the access token because automated-auth's password sign-in
	// returns no idToken; one, when present, must name the same user and
	// organization.
	claims := map[string]any{"sub": access.Sub, "org_id": access.OrgID}
	if access.Email != "" {
		claims["email"] = access.Email // shown in the app's header
	}
	if out.IDToken != "" {
		id, err := idTokenClaims(out.IDToken)
		if err != nil || id["sub"] != access.Sub || id["org_id"] != s.OrgID {
			return BrowserToken{}, ErrBrowserLogin
		}
		claims = id
	}
	return BrowserToken{access: out.AccessToken, life: life, Claims: claims, Expires: expires}, nil
}

type accessClaims struct {
	Sub   string          `json:"sub"`
	OrgID string          `json:"org_id"`
	Email string          `json:"https://trmlabs.com/email"` // set by the staging tenant's login action
	Aud   json.RawMessage `json:"aud"`
	Exp   int64           `json:"exp"`
}

// hasAudience reports whether aud, a string or a list, names audience.
func (c accessClaims) hasAudience(audience string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == audience
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == audience {
			return true
		}
	}
	return false
}

// accessTokenClaims reads the access token's payload. The token came from
// the broker's own sign-in over verified TLS; the API checks its signature.
func accessTokenClaims(token string) (accessClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return accessClaims{}, errors.New("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return accessClaims{}, err
	}
	var c accessClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return accessClaims{}, err
	}
	return c, nil
}

// revoke revokes a refresh token at the app's Auth0 tenant, through the
// Auth0 client the password-realm login uses. The app's client is public,
// so the request carries its client ID and no secret. It is tried twice; a
// failure is audited and does not fail the sign-in, since the broker keeps
// the token nowhere.
func (a *Auth0Tokens) revoke(ctx context.Context, e *Entry, token string) {
	outcome, status, started := "revoke_failed", 0, time.Now()
	defer func() {
		if a.Revoked != nil {
			a.Revoked(e.Name, outcome, status, time.Since(started))
		}
	}()
	if a.Client == nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"client_id": e.BrowserSession.Auth0.ClientID, "token": token})
	defer clear(body)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	client := *a.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(revokeBackoff):
			case <-ctx.Done():
				return
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.BrowserSession.Auth0.Domain+"/oauth/revoke", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Close = true
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		status = resp.StatusCode
		if status == http.StatusOK {
			outcome = "refresh_revoked"
			return
		}
	}
}

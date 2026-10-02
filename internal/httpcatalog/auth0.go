package httpcatalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BrowserToken is a test user's access token and the non-secret claims of
// their ID token. It prints as its expiry only.
type BrowserToken struct {
	access  string
	life    time.Duration
	Claims  map[string]any // from the ID token; identity, not authority
	Expires time.Time
}

func (t BrowserToken) Value() string { return t.access }
func (t BrowserToken) String() string {
	return "browser-token(expires " + t.Expires.UTC().Format(time.RFC3339) + ")"
}
func (t BrowserToken) GoString() string           { return t.String() }
func (t BrowserToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.String())) }

// Auth0Tokens logs test users in with Auth0's password-realm grant through a
// confidential client and caches each access token until a quarter of its
// life remains. The user's password and the client secret come from Vault on
// each login and are never cached here.
type Auth0Tokens struct {
	Keys interface {
		Get(context.Context, KeyRef) (Secret, error)
	}
	Client *http.Client // must dial only the Auth0 domains in the catalog
	Now    func() time.Time

	mu     sync.Mutex
	cache  map[string]BrowserToken
	flight map[string]*sync.Mutex
}

var ErrBrowserLogin = errors.New("browser test-user login failed")

func (a *Auth0Tokens) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Auth0Tokens) fresh(t BrowserToken) bool {
	left := t.Expires.Sub(a.now())
	return left > time.Minute && left > t.life/4
}

// Token returns the current access token for a browser-session entry.
// Concurrent misses for one entry share a single login.
func (a *Auth0Tokens) Token(ctx context.Context, e *Entry) (BrowserToken, error) {
	if e == nil || e.BrowserSession == nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	key := cacheKey(e)
	a.mu.Lock()
	if a.cache == nil {
		a.cache, a.flight = map[string]BrowserToken{}, map[string]*sync.Mutex{}
	}
	if t, ok := a.cache[key]; ok && a.fresh(t) {
		a.mu.Unlock()
		return t, nil
	}
	flight := a.flight[key]
	if flight == nil {
		flight = &sync.Mutex{}
		a.flight[key] = flight
	}
	a.mu.Unlock()
	flight.Lock()
	defer flight.Unlock()
	a.mu.Lock()
	if t, ok := a.cache[key]; ok && a.fresh(t) {
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()
	t, err := a.login(ctx, e.BrowserSession)
	if err != nil {
		return BrowserToken{}, err
	}
	a.mu.Lock()
	a.cache[key] = t
	a.mu.Unlock()
	return t, nil
}

// Invalidate drops an entry's token after the API refused it.
func (a *Auth0Tokens) Invalidate(e *Entry) {
	a.mu.Lock()
	delete(a.cache, cacheKey(e))
	a.mu.Unlock()
}

func cacheKey(e *Entry) string {
	b := e.BrowserSession
	return strings.Join([]string{e.Name, b.Auth0.Domain, b.Auth0.Audience, b.User.Mount, b.User.Path}, "\x00")
}

func (a *Auth0Tokens) login(ctx context.Context, b *BrowserSessionBinding) (BrowserToken, error) {
	values := map[string]string{}
	for name, ref := range map[string]KeyRef{
		"username": b.User.Field("email"), "password": b.User.Field("password"),
		"client_id": b.Auth0.TokenClient.Field("client_id"), "client_secret": b.Auth0.TokenClient.Field("client_secret"),
	} {
		s, err := a.Keys.Get(ctx, ref)
		if err != nil || s.Value() == "" {
			return BrowserToken{}, ErrBrowserLogin
		}
		values[name] = s.Value()
	}
	body, _ := json.Marshal(map[string]string{
		"grant_type": "http://auth0.com/oauth/grant-type/password-realm", "realm": b.Auth0.Realm,
		"audience": b.Auth0.Audience, "scope": b.Auth0.Scope,
		"username": values["username"], "password": values["password"],
		"client_id": values["client_id"], "client_secret": values["client_secret"],
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+b.Auth0.Domain+"/oauth/token", bytes.NewReader(body))
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	req.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	issued := a.now()
	resp, err := client.Do(req)
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		// Auth0's error text can echo the username; it is not passed on.
		return BrowserToken{}, ErrBrowserLogin
	}
	var out struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(data, &out) != nil || out.AccessToken == "" || out.IDToken == "" || out.ExpiresIn < 120 ||
		!strings.EqualFold(out.TokenType, "Bearer") {
		return BrowserToken{}, ErrBrowserLogin
	}
	claims, err := idTokenClaims(out.IDToken)
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	return BrowserToken{access: out.AccessToken, life: life, Claims: claims, Expires: issued.Add(life)}, nil
}

// Claims a browser seed may carry: who the user is, never what proves it.
// Protocol and session claims (nonce, at_hash, sid and the like) are dropped;
// the seed sets its own iss, aud, iat and exp.
var protocolClaims = map[string]bool{"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true, "azp": true,
	"nonce": true, "auth_time": true, "at_hash": true, "c_hash": true, "acr": true, "amr": true, "sid": true, "cnf": true, "sub_jwk": true}

// idTokenClaims reads the ID token's payload. The token came straight from
// Auth0 over verified TLS in answer to the broker's own login, so its
// signature is not what makes it trustworthy here.
func idTokenClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, err
	}
	claims := map[string]any{}
	for k, v := range all {
		if !protocolClaims[k] {
			claims[k] = v
		}
	}
	if s, _ := claims["sub"].(string); s == "" {
		return nil, errors.New("ID token has no subject")
	}
	return claims, nil
}

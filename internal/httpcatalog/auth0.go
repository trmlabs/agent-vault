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

// Auth0Tokens logs test users in and caches each access token until a
// quarter of its life remains. An entry logs in with Auth0's password-realm
// grant through a confidential client, or, when it names one, through TRM's
// automated-auth service (see automatedAuthLogin). The user's password and
// the client secret or service key come from Vault on each login and are
// never cached here. The login keeps no refresh token and never follows a
// redirect: the request body holds the secrets.
type Auth0Tokens struct {
	Keys interface {
		Get(context.Context, KeyRef) (Secret, error)
	}
	Client        *http.Client // must dial only the Auth0 domains in the catalog
	AutomatedAuth *http.Client // must dial only the automated-auth services in the catalog
	// Revoked reports each refresh-token revocation after an automated-auth
	// sign-in, for the audit trail: outcome "refresh_revoked" or
	// "revoke_failed", and Auth0's status (0 without an answer).
	Revoked func(binding, outcome string, status int)
	Now     func() time.Time

	mu     sync.Mutex
	states map[string]*signIn
}

// signIn is one entry's sign-in state: its last token, its last attempt,
// and the attempt in progress.
type signIn struct {
	token     BrowserToken
	held      bool // token is set
	attempted time.Time
	call      *signInCall
}

// signInCall is a sign-in in progress, shared by every request waiting for it.
type signInCall struct {
	done  chan struct{}
	token BrowserToken
	err   error
}

var ErrBrowserLogin = errors.New("browser test-user login failed")

// reloginInterval bounds sign-ins to one attempt per entry per interval,
// whatever the outcome: a worker can make the API refuse a request, or a
// sign-in fail, on purpose, and each attempt is a real login (for
// automated-auth, a browser on a shared service) that also mints a refresh
// token. Invalidate also keeps a token younger than this.
const reloginInterval = time.Minute

// signInTimeout bounds a sign-in, which runs detached from the request that
// started it.
const signInTimeout = 90 * time.Second

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
// Requests that need a sign-in share one attempt, which runs detached from
// any one of them: a request that gives up ends only its own wait. After an
// attempt, the entry makes no other for reloginInterval; until then it
// serves its last token while that is still valid, and otherwise fails.
func (a *Auth0Tokens) Token(ctx context.Context, e *Entry) (BrowserToken, error) {
	if e == nil || e.BrowserSession == nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	key := cacheKey(e)
	a.mu.Lock()
	if a.states == nil {
		a.states = map[string]*signIn{}
	}
	st := a.states[key]
	if st == nil {
		st = &signIn{}
		a.states[key] = st
	}
	now := a.now()
	call := st.call
	switch {
	case st.held && a.fresh(st.token):
		t := st.token
		a.mu.Unlock()
		return t, nil
	case call != nil:
	case !st.attempted.IsZero() && now.Sub(st.attempted) < reloginInterval:
		t, held := st.token, st.held && st.token.Expires.After(now)
		a.mu.Unlock()
		if !held {
			return BrowserToken{}, ErrBrowserLogin
		}
		return t, nil
	default:
		call = &signInCall{done: make(chan struct{})}
		st.call, st.attempted = call, now
		go a.signIn(context.WithoutCancel(ctx), e, st, call)
	}
	a.mu.Unlock()
	select {
	case <-call.done:
		return call.token, call.err
	case <-ctx.Done():
		return BrowserToken{}, ErrBrowserLogin
	}
}

func (a *Auth0Tokens) signIn(ctx context.Context, e *Entry, st *signIn, call *signInCall) {
	ctx, cancel := context.WithTimeout(ctx, signInTimeout)
	defer cancel()
	t, err := a.login(ctx, e)
	a.mu.Lock()
	defer a.mu.Unlock()
	st.call = nil
	if err == nil {
		st.token, st.held = t, true
	} else if st.held && st.token.Expires.After(a.now()) {
		// A failed renewal leaves the last token serving until it expires.
		t, err = st.token, nil
	}
	call.token, call.err = t, err
	close(call.done)
}

// Invalidate drops an entry's token after the API refused it, unless the
// token is younger than reloginInterval.
func (a *Auth0Tokens) Invalidate(e *Entry) {
	key := cacheKey(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.states[key]
	if st == nil || !st.held || a.now().Sub(st.token.Expires.Add(-st.token.life)) < reloginInterval {
		return
	}
	st.token, st.held = BrowserToken{}, false
}

func cacheKey(e *Entry) string {
	b := e.BrowserSession
	parts := []string{e.Name, b.Auth0.Domain, b.Auth0.Audience, b.Auth0.Login, b.Auth0.Realm, b.Auth0.TokenClient.Mount, b.Auth0.TokenClient.Path,
		b.User.Mount, b.User.Path}
	if s := b.AutomatedAuth; s != nil {
		parts = append(parts, s.URL, s.Profile, s.OrgID, s.Key.Mount, s.Key.Path)
	}
	return strings.Join(parts, "\x00")
}

func (a *Auth0Tokens) login(ctx context.Context, e *Entry) (BrowserToken, error) {
	b := e.BrowserSession
	if b.Auth0.Login == "automated-auth" {
		return a.automatedAuthLogin(ctx, e)
	}
	if b.AutomatedAuth != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
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
		"audience": b.Auth0.Audience, "scope": loginScope(b.Auth0.Scope),
		"username": values["username"], "password": values["password"],
		"client_id": values["client_id"], "client_secret": values["client_secret"],
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+b.Auth0.Domain+"/oauth/token", bytes.NewReader(body))
	if err != nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Client == nil {
		return BrowserToken{}, ErrBrowserLogin
	}
	// A 307 or 308 would re-send the body, secrets included, to wherever it
	// points; the login answers from the Auth0 domain or not at all.
	client := *a.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
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

// loginScope is the app's scope without offline_access. The broker never
// uses a refresh token, and each one Auth0 issued would stay live after the
// access token is dropped.
func loginScope(scope string) string {
	var kept []string
	for _, s := range strings.Fields(scope) {
		if s != "offline_access" {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " ")
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

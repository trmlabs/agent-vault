package httpcatalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Synthetic test-user values; never real credentials.
var browserSecrets = map[string]string{"email": "qa-user@example.test", "password": "synthetic-password-9c1",
	"client_id": "synthetic-confidential-client", "client_secret": "synthetic-client-secret-4f2"}

type fieldVault struct{}

func (fieldVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	data := map[string]interface{}{}
	for k, v := range browserSecrets {
		data[k] = v
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

func browserEntryJSON(extra string) string {
	return `{"name":"staging-app","kind":"browser-session","host":"api.example.com","placeholder":"__vault_STAGING_APP__",
		"pools":["database-developers"]` + extra + `,"browserSession":{"appHost":"app.example.com",
		"auth0":{"domain":"example.com","clientID":"spaClient1","audience":"https://api.example.com","realm":"Username-Password-Authentication",
		"tokenClient":{"mount":"gatehouse","path":"browser/client"}},"user":{"mount":"gatehouse","path":"browser/qa-user"}}}`
}

func TestBrowserSessionEntry(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + browserEntryJSON("") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.Port != 443 || e.PathPrefixes[0] != "/" || e.BrowserSession.Auth0.Scope != "openid profile email offline_access" {
		t.Fatalf("defaults: %+v", e)
	}
	if !c.HasHost("app.example.com", 443) || !c.HasHost("api.example.com", 443) || c.HasHost("example.com", 443) {
		t.Fatal("tunnel hosts wrong")
	}
	cases := []struct {
		host, method, path, pool string
		app, seed                bool
		err                      error
	}{
		{"app.example.com", "GET", "/index.html", "database-developers", true, false, nil},
		{"app.example.com", "POST", "/", "database-developers", true, false, ErrMethod},
		{"app.example.com", "GET", "/", "other", true, false, ErrPool},
		{"api.example.com", "OPTIONS", "/v1/cases", "database-developers", false, false, nil},
		{"api.example.com", "DELETE", "/v1/cases/1", "database-developers", false, false, nil},
		{"api.example.com", "GET", BrowserSeedPath, "database-developers", false, true, nil},
		{"api.example.com", "POST", BrowserSeedPath, "database-developers", false, true, ErrMethod},
		{"api.example.com", "GET", "/v1", "other", false, false, ErrPool},
	}
	for _, tc := range cases {
		m, ok, err := c.BrowserMatch(tc.host, 443, tc.method, tc.path, tc.pool)
		if !ok || m.App != tc.app || m.Seed != tc.seed || !errors.Is(err, tc.err) {
			t.Errorf("%s %s %s %s: %+v %v %v", tc.host, tc.method, tc.path, tc.pool, m, ok, err)
		}
	}
	if _, ok, _ := c.BrowserMatch("example.com", 443, "GET", "/", "database-developers"); ok {
		t.Fatal("unrelated host routed to the browser entry")
	}
	narrow, err := Parse([]byte(`{"entries":[` + browserEntryJSON(`,"pathPrefixes":["/v1"]`) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := narrow.BrowserMatch("api.example.com", 443, "GET", "/admin", "database-developers"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("path outside the prefixes: %v", err)
	}
}

func TestBrowserSessionEntryRejects(t *testing.T) {
	header := `{"name":"vendor","host":"app.example.com","pathPrefixes":["/v1"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",
		"placeholder":"__vault_V__","key":{"mount":"gatehouse","path":"v","field":"k"},"pools":["database-developers"]}`
	for name, catalog := range map[string]string{
		"no settings":       `{"entries":[{"name":"x","kind":"browser-session","host":"api.example.com","placeholder":"__vault_X__","pools":["p"]}]}`,
		"app is api":        `{"entries":[` + strings.Replace(browserEntryJSON(""), `"appHost":"app.example.com"`, `"appHost":"api.example.com"`, 1) + `]}`,
		"no openid":         `{"entries":[` + strings.Replace(browserEntryJSON(""), `"realm"`, `"scope":"profile email","realm"`, 1) + `]}`,
		"key set":           `{"entries":[` + browserEntryJSON(`,"key":{"mount":"gatehouse","path":"v","field":"k"}`) + `]}`,
		"methods set":       `{"entries":[` + browserEntryJSON(`,"methods":["GET"]`) + `]}`,
		"cookie forwarded":  `{"entries":[` + browserEntryJSON(`,"forwardHeaders":["Cookie"]`) + `]}`,
		"app host shared":   `{"entries":[` + browserEntryJSON("") + `,` + header + `]}`,
		"settings on other": `{"entries":[` + strings.Replace(header, `"pools"`, `"browserSession":{"appHost":"x.example.com"},"pools"`, 1) + `]}`,
	} {
		if _, err := Parse([]byte(catalog)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func fakeAuth0(t *testing.T, lifetime int, logins *atomic.Int32, status *atomic.Int32) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/oauth/token" || body["grant_type"] != "http://auth0.com/oauth/grant-type/password-realm" ||
			body["username"] != browserSecrets["email"] || body["password"] != browserSecrets["password"] ||
			body["client_id"] != browserSecrets["client_id"] || body["client_secret"] != browserSecrets["client_secret"] ||
			body["realm"] != "Username-Password-Authentication" || body["audience"] != "https://api.example.com" ||
			body["scope"] != "openid profile email" { // the broker never asks for a refresh token
			http.Error(w, `{"error":"invalid_grant","error_description":"Wrong email or password for qa-user@example.test"}`, http.StatusForbidden)
			return
		}
		if s := status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		claims, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": "org_synthetic", "email": "qa-user@example.test",
			"nonce": "n", "sid": "session", "at_hash": "h", "iss": "https://example.com/", "aud": "spaClient1"})
		idToken := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("synthetic-access-token-%d", logins.Load()),
			"id_token": idToken, "expires_in": lifetime, "token_type": "Bearer"})
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	client := srv.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return srv, client
}

func TestAuth0TokensLoginCacheAndRefresh(t *testing.T) {
	var logins, status atomic.Int32
	_, client := fakeAuth0(t, 3600, &logins, &status)
	c, err := Parse([]byte(`{"entries":[` + browserEntryJSON("") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	entry := &c.Entries()[0]
	now := time.Now()
	tokens := &Auth0Tokens{Keys: &Keys{Vault: fieldVault{}}, Client: client, Now: func() time.Time { return now }}
	first, err := tokens.Token(context.Background(), entry)
	if err != nil || first.Value() != "synthetic-access-token-1" {
		t.Fatalf("login: %v", err)
	}
	if first.Claims["sub"] != "auth0|qa-user" || first.Claims["org_id"] != "org_synthetic" || first.Claims["nonce"] != nil || first.Claims["sid"] != nil {
		t.Fatalf("claims: %v", first.Claims)
	}
	if s := fmt.Sprint(first) + fmt.Sprintf("%v %+v %#v", first, first, first); strings.Contains(s, "synthetic-access-token") {
		t.Fatal("token printed")
	}
	if again, _ := tokens.Token(context.Background(), entry); again.Value() != first.Value() || logins.Load() != 1 {
		t.Fatal("token not cached")
	}
	now = now.Add(46 * time.Minute) // a quarter of an hour's life left
	if renewed, _ := tokens.Token(context.Background(), entry); renewed.Value() != "synthetic-access-token-2" {
		t.Fatal("token not refreshed before expiry")
	}
	tokens.Invalidate(entry) // a minute-old token is kept: a worker cannot force logins
	if kept, _ := tokens.Token(context.Background(), entry); kept.Value() != "synthetic-access-token-2" {
		t.Fatal("fresh token dropped")
	}
	now = now.Add(reloginInterval)
	tokens.Invalidate(entry)
	if after, _ := tokens.Token(context.Background(), entry); after.Value() != "synthetic-access-token-3" {
		t.Fatal("invalidated token reused")
	}
	status.Store(http.StatusTooManyRequests)
	now = now.Add(reloginInterval)
	tokens.Invalidate(entry)
	if _, err := tokens.Token(context.Background(), entry); !errors.Is(err, ErrBrowserLogin) {
		t.Fatalf("failed login: %v", err)
	}
}

func TestAuth0TokensRefuseBadLogins(t *testing.T) {
	var logins, status atomic.Int32
	_, client := fakeAuth0(t, 60, &logins, &status) // below the two-minute floor
	c, _ := Parse([]byte(`{"entries":[` + browserEntryJSON("") + `]}`))
	tokens := &Auth0Tokens{Keys: &Keys{Vault: fieldVault{}}, Client: client}
	if _, err := tokens.Token(context.Background(), &c.Entries()[0]); err == nil {
		t.Fatal("short-lived token accepted")
	}
	wrong, _ := Parse([]byte(`{"entries":[` + strings.Replace(browserEntryJSON(""), "Username-Password-Authentication", "other-realm", 1) + `]}`))
	_, err := tokens.Token(context.Background(), &wrong.Entries()[0])
	if err == nil || strings.Contains(err.Error(), "qa-user") {
		t.Fatalf("refused login leaked or passed: %v", err)
	}
	if _, err := (&Auth0Tokens{Keys: &Keys{Vault: fieldVault{}}}).Token(context.Background(), &c.Entries()[0]); err == nil {
		t.Fatal("login without a guarded client")
	}
}

// The login body holds the test user's password and the client secret; a
// redirect, even a 307 that would re-send it, is never followed.
func TestAuth0LoginNeverFollowsARedirect(t *testing.T) {
	var elsewhere atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			elsewhere.Add(1)
			return
		}
		http.Redirect(w, r, "https://collector.example.com/steal", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	client := srv.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	c, _ := Parse([]byte(`{"entries":[` + browserEntryJSON("") + `]}`))
	tokens := &Auth0Tokens{Keys: &Keys{Vault: fieldVault{}}, Client: client}
	if _, err := tokens.Token(context.Background(), &c.Entries()[0]); !errors.Is(err, ErrBrowserLogin) || elsewhere.Load() != 0 {
		t.Fatalf("redirect followed: err=%v requests elsewhere=%d", err, elsewhere.Load())
	}
}

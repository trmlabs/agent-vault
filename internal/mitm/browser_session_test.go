package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

const browserPlaceholder = "__vault_STAGING_APP__"

// Synthetic test-user secrets; never real credentials.
type browserVault struct{ down *atomic.Bool }

func (v browserVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	if v.down != nil && v.down.Load() {
		return nil, errors.New("vault unreachable")
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{
		"email": "qa-user@example.test", "password": "synthetic-password-9c1", "private_key": "synthetic-automated-auth-key-7e3",
		"client_id": "synthetic-confidential-client", "client_secret": "synthetic-client-secret-4f2"},
		"metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

type browserFixture struct {
	client    *http.Client
	audit     *adapterAudit
	sessions  *scopeResolver
	logins    atomic.Int32
	mu        sync.Mutex
	seen      map[string]http.Header // last request headers per host
	apiCalls  atomic.Int32
	reject    atomic.Int32 // status the API answers with, when set
	refusal   atomic.Value // WWW-Authenticate on a refusal, when set
	clock     atomic.Int64 // nanoseconds the token cache's clock runs ahead
	loginErr  atomic.Bool  // automated-auth refuses the login, naming the user
	vaultDown atomic.Bool  // every Vault read fails
	revokes   atomic.Int32 // refresh-token revocations Auth0 received
	revokeErr atomic.Bool  // Auth0 refuses revocations
	proxy     *Proxy
}

func (f *browserFixture) headers(host string) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[host]
}

// One TLS server plays the app, its API and Auth0, told apart by Host.
func newBrowserFixture(t *testing.T) *browserFixture { return newBrowserFixtureWith(t, false, nil) }

// newBrowserFixtureWith logs the test user in through automated-auth when
// automated is set, and sends the proxy's log to logger when one is given.
func newBrowserFixtureWith(t *testing.T, automated bool, logger *slog.Logger) *browserFixture {
	t.Helper()
	f := &browserFixture{audit: &adapterAudit{}, seen: map[string]http.Header{}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"},
		DNSNames: []string{"app.example.com", "api.example.com", "auth.example.com", "automated-auth.example.com"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		f.mu.Lock()
		f.seen[host] = r.Header.Clone()
		f.mu.Unlock()
		switch host {
		case "auth.example.com":
			if r.URL.Path == "/oauth/revoke" {
				f.revokes.Add(1)
				var revoke map[string]string
				if json.NewDecoder(r.Body).Decode(&revoke) != nil || revoke["client_id"] != "spaClient1" || revoke["token"] != "synthetic-refresh-token-5d8" || f.revokeErr.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				return
			}
			f.logins.Add(1)
			claims, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": "org_synthetic", "email": "qa-user@example.test", "nonce": "n"})
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("synthetic-real-access-token-%d", f.logins.Load()),
				"id_token": "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".sig", "expires_in": 3600, "token_type": "Bearer"})
		case "automated-auth.example.com":
			f.logins.Add(1)
			var login map[string]string
			if json.NewDecoder(r.Body).Decode(&login) != nil || login["privateKey"] != "synthetic-automated-auth-key-7e3" ||
				login["orgId"] != "org_synthetic" || login["password"] != "synthetic-password-9c1" || f.loginErr.Load() {
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprint(w, `{"error":{"code":"token_extraction_failed","message":"no token for qa-user@example.test"}}`)
				return
			}
			payload, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": "org_synthetic", "aud": []string{"https://api.example.com"},
				"exp": time.Now().Add(time.Hour).Unix()})
			access := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + fmt.Sprintf(".synthetic-real-access-token-%d", f.logins.Load())
			token, _ := json.Marshal(map[string]any{"body": map[string]any{"access_token": access, "refresh_token": "synthetic-refresh-token-5d8"}})
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": access, "refreshToken": "synthetic-refresh-token-5d8",
				"expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "browserAuthSeed": map[string]any{"localStorageEntries": []map[string]string{
					{"key": "@@auth0spajs@@::spaClient1::https://api.example.com::openid profile email offline_access", "value": string(token)}}}})
		case "app.example.com":
			w.Header().Set("Set-Cookie", "app_session=synthetic-app-session; Secure")
			fmt.Fprint(w, "<html>app</html>")
		case "api.example.com":
			f.apiCalls.Add(1)
			want := fmt.Sprintf("synthetic-real-access-token-%d", f.logins.Load())
			if status := f.reject.Load(); status != 0 {
				if challenge, _ := f.refusal.Load().(string); challenge != "" {
					w.Header().Set("WWW-Authenticate", challenge)
				}
				w.WriteHeader(int(status))
				return
			}
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") || !strings.HasSuffix(got, want) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
			w.Header().Set("Set-Cookie", "api_session=synthetic-api-session; Secure; HttpOnly")
			switch r.URL.Path {
			case "/v1/echo":
				fmt.Fprint(w, r.Header.Get("Authorization")) // #nosec G705 -- test upstream echoing a synthetic token
			case "/v1/stream":
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: one\n\n")
				w.(http.Flusher).Flush()
				fmt.Fprint(w, "data: two\n\n")
			default:
				fmt.Fprint(w, `{"cases":[]}`)
			}
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	login := `,"realm":"Username-Password-Authentication","tokenClient":{"mount":"gatehouse","path":"browser/client"}},`
	if automated {
		login = `,"login":"automated-auth"},"automatedAuth":{"url":"https://automated-auth.example.com","profile":"app-staging","orgID":"org_synthetic",
			"key":{"mount":"gatehouse","path":"browser/automated-auth"}},`
	}
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[{"name":"staging-app","kind":"browser-session","host":"api.example.com",
		"placeholder":"` + browserPlaceholder + `","pools":["database-developers"],"pathPrefixes":["/v1","/organizations","/users","/users-organizations"],"readOnlyPaths":["/v1/reports"],
		"deniedPaths":["/v1/parent-organizations/*/users","/v1/intel-vault"],
		"browserSession":{"appHost":"app.example.com","auth0":{"domain":"auth.example.com","clientID":"spaClient1","audience":"https://api.example.com"` + login + `
		"user":{"mount":"gatehouse","path":"browser/qa-user"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	authClient := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: upstreamRoots}}}
	tokens := &httpcatalog.Auth0Tokens{Keys: &httpcatalog.Keys{Vault: browserVault{down: &f.vaultDown}}, Client: authClient, AutomatedAuth: authClient,
		Revoked: func(binding, outcome string, status int, took time.Duration) {
			_ = f.audit.Record(auditchain.Event{Event: auditchain.EventHTTPResponse, Binding: binding + "/revoke", Outcome: outcome, Status: status, Duration: took.Milliseconds()})
		},
		Now: func() time.Time { return time.Now().Add(time.Duration(f.clock.Load())) }}
	f.sessions = &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "database-developers",
		WorkloadID: "pod-uid-1", VaultRole: "proxy", NotAfter: time.Now().Add(30 * time.Minute).Truncate(time.Second)}}
	proxyURL, roots, p := setupProxy(t, f.sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: "unused"}, Audit: f.audit, BrowserTokens: tokens}
		if logger != nil {
			o.Logger = logger
		}
	})
	p.upstream.TLSClientConfig.RootCAs = upstreamRoots
	p.upstream.DialContext = dial
	f.proxy = p
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

// browserResult is what a test reads of a response, after its body is closed.
type browserResult struct {
	StatusCode int
	Header     http.Header
}

func (f *browserFixture) do(t *testing.T, method, rawURL string, mutate func(*http.Request)) (*browserResult, string) {
	t.Helper()
	r, _ := http.NewRequest(method, rawURL, nil)
	if mutate != nil {
		mutate(r)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		return nil, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	for _, secret := range []string{"synthetic-real-access-token", "synthetic-password", "synthetic-client-secret", "synthetic-api-session", "synthetic-app-session",
		"synthetic-refresh-token", "synthetic-automated-auth-key"} {
		if strings.Contains(string(data), secret) || strings.Contains(fmt.Sprint(resp.Header), secret) {
			t.Fatalf("%s reached the browser", secret)
		}
	}
	return &browserResult{StatusCode: resp.StatusCode, Header: resp.Header}, string(data)
}

func bearerPlaceholder(r *http.Request) { r.Header.Set("Authorization", "Bearer "+browserPlaceholder) }

// The seed is a Playwright storage state for the app's origin: the
// placeholder where auth0-spa-js keeps the access token, an unsigned ID token
// with the test user's sub and org_id, and an expiry at the Pod's deadline.
func TestBrowserSeedHoldsOnlyPlaceholders(t *testing.T) {
	f := newBrowserFixture(t)
	resp, body := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil)
	if resp == nil || resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("seed: %v %s", resp, body)
	}
	var state struct {
		Cookies []struct {
			Name, Domain string
			Expires      float64
		}
		Origins []struct {
			Origin       string
			LocalStorage []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal([]byte(body), &state); err != nil || len(state.Origins) != 1 || state.Origins[0].Origin != "https://app.example.com" {
		t.Fatalf("storage state: %v %s", err, body)
	}
	deadline := f.sessions.scope.NotAfter.Unix()
	if len(state.Cookies) != 1 || state.Cookies[0].Name != "auth0.spaClient1.is.authenticated" || int64(state.Cookies[0].Expires) != deadline {
		t.Fatalf("cookie: %+v", state.Cookies)
	}
	items := map[string]string{}
	for _, item := range state.Origins[0].LocalStorage {
		items[item.Name] = item.Value
	}
	var tokenEntry struct {
		Body      map[string]any
		ExpiresAt int64
	}
	if err := json.Unmarshal([]byte(items["@@auth0spajs@@::spaClient1::https://api.example.com::openid profile email offline_access"]), &tokenEntry); err != nil ||
		tokenEntry.Body["access_token"] != browserPlaceholder || tokenEntry.ExpiresAt != deadline || tokenEntry.Body["refresh_token"] != nil {
		t.Fatalf("token entry: %v %+v", err, tokenEntry)
	}
	var userEntry struct {
		IDToken      string `json:"id_token"`
		DecodedToken struct {
			Claims map[string]any
			User   map[string]any
		} `json:"decodedToken"`
	}
	if err := json.Unmarshal([]byte(items["@@auth0spajs@@::spaClient1::@@user@@"]), &userEntry); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(userEntry.IDToken, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if len(parts) != 3 || parts[2] != "" || !strings.Contains(string(header), `"alg":"none"`) {
		t.Fatal("ID token is not an unsigned JWT")
	}
	claims := userEntry.DecodedToken.Claims
	if claims["sub"] != "auth0|qa-user" || claims["org_id"] != "org_synthetic" || claims["nonce"] != nil || int64(claims["exp"].(float64)) != deadline ||
		claims["aud"] != "spaClient1" || userEntry.DecodedToken.User["email"] != "qa-user@example.test" {
		t.Fatalf("claims: %v", claims)
	}
	if last := f.audit.last(); last.Event != auditchain.EventHTTPResponse || last.Binding != "staging-app" || last.PodUID != "pod-uid-1" {
		t.Fatalf("audit: %+v", last)
	}
}

// The API gets the real token for the placeholder; the browser never sees it,
// nor any cookie either side sets. Preflight and streaming pass.
func TestBrowserAPISwapsPlaceholderAndStripsCookies(t *testing.T) {
	f := newBrowserFixture(t)
	resp, body := f.do(t, "GET", "https://api.example.com/v1/cases", func(r *http.Request) {
		bearerPlaceholder(r)
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Cookie", "leak=1")
	})
	if resp == nil || resp.StatusCode != 200 || body != `{"cases":[]}` || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("api: %v %q", resp, body)
	}
	seen := f.headers("api.example.com")
	if seen.Get("Origin") != "https://app.example.com" || seen.Get("Cookie") != "" {
		t.Fatalf("upstream headers: %v", seen)
	}
	if resp, _ := f.do(t, "OPTIONS", "https://api.example.com/v1/cases", func(r *http.Request) {
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Access-Control-Request-Method", "POST")
	}); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("preflight: %v", resp)
	}
	if resp, body := f.do(t, "GET", "https://api.example.com/v1/stream", bearerPlaceholder); resp == nil || body != "data: one\n\ndata: two\n\n" {
		t.Fatalf("stream: %v %q", resp, body)
	}
	// An API that echoes the token never gets it to the browser.
	if resp, body := f.do(t, "GET", "https://api.example.com/v1/echo", bearerPlaceholder); resp != nil && strings.Contains(body, "Bearer synthetic") {
		t.Fatal("echoed token reached the browser")
	}
	if f.logins.Load() != 1 {
		t.Fatalf("logged in %d times, want once", f.logins.Load())
	}
}

func TestBrowserRefusals(t *testing.T) {
	f := newBrowserFixture(t)
	for name, tc := range map[string]struct {
		method, url string
		mutate      func(*http.Request)
		status      int
		outcome     string
	}{
		"own token":            {"GET", "https://api.example.com/v1/cases", func(r *http.Request) { r.Header.Set("Authorization", "Bearer real-looking") }, 400, "credential_header"},
		"placeholder in query": {"GET", "https://api.example.com/v1/cases?q=" + browserPlaceholder, bearerPlaceholder, 400, "request_shape"},
		"websocket":            {"GET", "https://api.example.com/v1/socket", func(r *http.Request) { bearerPlaceholder(r); r.Header.Set("Upgrade", "websocket") }, 400, "request_shape"},
		"seed by POST":         {"POST", "https://api.example.com" + httpcatalog.BrowserSeedPath, nil, 405, "method"},
		"credential to app":    {"GET", "https://app.example.com/", bearerPlaceholder, 400, "credential_header"},
		"post to app":          {"POST", "https://app.example.com/", nil, 405, "method"},
	} {
		calls := f.apiCalls.Load()
		resp, _ := f.do(t, tc.method, tc.url, tc.mutate)
		if resp == nil || resp.StatusCode != tc.status || f.audit.last().Outcome != tc.outcome || f.apiCalls.Load() != calls {
			t.Errorf("%s: %v %q", name, resp, f.audit.last().Outcome)
		}
	}
	f.sessions.set(&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "other-pool", WorkloadID: "pod-uid-2", VaultRole: "proxy"})
	if resp, _ := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil); resp == nil || resp.StatusCode != 403 || f.audit.last().Outcome != "pool" {
		t.Fatalf("ungranted pool got a seed: %v", resp)
	}
}

// The app loads with no credential and none of its cookies; a token the API
// refuses as invalid is dropped and the next call logs in again, but no more
// than once a minute, and a refusal that is not about the token never does.
func TestBrowserAppAndTokenRenewal(t *testing.T) {
	f := newBrowserFixture(t)
	resp, body := f.do(t, "GET", "https://app.example.com/index.html", func(r *http.Request) { r.Header.Set("Cookie", "leak=1") })
	if resp == nil || resp.StatusCode != 200 || body != "<html>app</html>" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("app: %v %q", resp, body)
	}
	if seen := f.headers("app.example.com"); seen.Get("Authorization") != "" || seen.Get("Cookie") != "" {
		t.Fatalf("app request carried a credential: %v", seen)
	}
	call := func(status int, logins int32) {
		t.Helper()
		if resp, _ := f.do(t, "GET", "https://api.example.com/v1/cases", bearerPlaceholder); resp == nil || resp.StatusCode != status || f.logins.Load() != logins {
			t.Fatalf("want %d after %d logins: %v logins=%d", status, logins, resp, f.logins.Load())
		}
	}
	refuse := func(status int32, challenge string) {
		t.Helper()
		f.reject.Store(status)
		f.refusal.Store(challenge)
		call(int(status), f.logins.Load())
		f.reject.Store(0)
	}
	call(200, 1)
	f.clock.Add(int64(2 * time.Minute))
	// Refusals that say nothing about the token keep it.
	refuse(http.StatusForbidden, "")
	refuse(http.StatusUnauthorized, `Bearer realm="api", error="insufficient_scope"`)
	call(200, 1)
	// A refusal of a fresh token keeps it too: a worker cannot force logins.
	f.clock.Store(0)
	refuse(http.StatusUnauthorized, "")
	call(200, 1)
	// Past the interval, an invalid-token refusal drops it.
	f.clock.Store(int64(2 * time.Minute))
	refuse(http.StatusUnauthorized, `Bearer realm="api", error="invalid_token", error_description="expired"`)
	call(200, 2)
	f.clock.Add(int64(2 * time.Minute))
	refuse(http.StatusUnauthorized, "")
	call(200, 3)
}

// TestBrowserSeedFile writes a seed for the real-browser check in
// scripts/browser-seed-check.mjs. It runs only when asked.
func TestBrowserSeedFile(t *testing.T) {
	out := os.Getenv("AV_BROWSER_SEED_OUT")
	if out == "" {
		t.Skip("set AV_BROWSER_SEED_OUT")
	}
	f := newBrowserFixture(t)
	resp, body := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil)
	if resp == nil || resp.StatusCode != 200 {
		t.Fatal("seed unavailable")
	}
	if err := os.WriteFile(out, []byte(body), 0o600); err != nil { // #nosec G703 -- path chosen by the person running the check
		t.Fatal(err)
	}
}

// lockedBuffer collects the proxy's log across its goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// With an automated-auth login the worker still gets only the placeholder
// seed, the API gets the real token, and neither the log nor the audit trail
// carries the service key, the password, or either token.
func TestBrowserAutomatedAuthKeepsSecretsBrokerSide(t *testing.T) {
	logs := &lockedBuffer{}
	f := newBrowserFixtureWith(t, true, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	resp, body := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil)
	if resp == nil || resp.StatusCode != 200 || !strings.Contains(body, browserPlaceholder) || !strings.Contains(body, "org_synthetic") {
		t.Fatalf("seed: %v %s", resp, body)
	}
	if resp, body := f.do(t, "GET", "https://api.example.com/v1/cases", bearerPlaceholder); resp == nil || resp.StatusCode != 200 || body != `{"cases":[]}` {
		t.Fatalf("api: %v %q", resp, body)
	}
	if f.logins.Load() != 1 || f.headers("automated-auth.example.com").Get("Content-Type") != "application/json" {
		t.Fatalf("logins: %d", f.logins.Load())
	}
	if f.revokes.Load() != 1 || !f.audited("staging-app/revoke", "refresh_revoked") {
		t.Fatalf("refresh token not revoked: %d", f.revokes.Load())
	}
	// A refused login, whose answer names the user, fails closed.
	f.loginErr.Store(true)
	f.clock.Store(int64(time.Hour))
	if resp, _ := f.do(t, "GET", "https://api.example.com/v1/cases", bearerPlaceholder); resp == nil || resp.StatusCode != http.StatusServiceUnavailable ||
		f.audit.last().Outcome != "token_unavailable" {
		t.Fatalf("refused login: %v %+v", resp, f.audit.last())
	}
	events, _ := json.Marshal(f.audit.all())
	for _, secret := range []string{"synthetic-automated-auth-key", "synthetic-password", "synthetic-real-access-token", "synthetic-refresh-token", "qa-user@example.test"} {
		if strings.Contains(string(events), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("%s in the audit trail or log", secret)
		}
	}
	if len(f.audit.all()) < 5 {
		t.Fatalf("audit trail too short to prove anything: %d events", len(f.audit.all()))
	}
}

func (f *browserFixture) audited(binding, outcome string) bool {
	for _, e := range f.audit.all() {
		if e.Binding == binding && e.Outcome == outcome {
			return true
		}
	}
	return false
}

// A failed revocation is retried once, then audited as revoke_failed; the
// sign-in still succeeds, since the broker keeps the refresh token nowhere.
func TestBrowserAutomatedAuthRevokeFailureAudited(t *testing.T) {
	f := newBrowserFixtureWith(t, true, nil)
	f.revokeErr.Store(true)
	if resp, body := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("seed: %v %s", resp, body)
	}
	if f.revokes.Load() != 2 || !f.audited("staging-app/revoke", "revoke_failed") || f.audited("staging-app/revoke", "refresh_revoked") {
		t.Fatalf("revocation: %d attempts, %+v", f.revokes.Load(), f.audit.all())
	}
}

// Vault unreachable: the sign-in fails closed with 503 and calls nothing.
func TestBrowserAutomatedAuthVaultErrorIs503(t *testing.T) {
	f := newBrowserFixtureWith(t, true, nil)
	f.vaultDown.Store(true)
	if resp, _ := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil); resp == nil || resp.StatusCode != http.StatusServiceUnavailable ||
		f.audit.last().Outcome != "token_unavailable" || f.logins.Load() != 0 {
		t.Fatalf("vault down: %v %+v logins=%d", resp, f.audit.last(), f.logins.Load())
	}
}

// The path guard refuses credential and account-admin routes anywhere in
// the path, and writes to read-only routes, before any sign-in or upstream
// call.
func TestBrowserPathGuard(t *testing.T) {
	f := newBrowserFixture(t)
	for _, tc := range []struct {
		method, path string
		status       int
		outcome      string
	}{
		{"GET", "/organizations/123/apiKey", 403, "denied_path"},
		{"POST", "/organizations/123/APIKEY", 403, "denied_path"},
		{"GET", "/organizations/123/api%4Bey", 403, "denied_path"},
		{"GET", "/organizations/123%2FapiKey", 403, "denied_path"},
		{"POST", "/users/mfa", 403, "denied_path"},
		{"POST", "/users/change-password", 403, "denied_path"},
		{"POST", "/v1/oauth/clients/x/rotate-secret", 403, "denied_path"},
		{"GET", "/v1/parent-organizations/1/users/2/roles", 403, "denied_path"},
		{"DELETE", "/v1/sessions/1", 403, "denied_path"},
		{"GET", "/v1/parent-organizations/7/users", 403, "denied_path"},
		{"GET", "/v1/parent-organizations/7/users/3/teams", 403, "denied_path"},
		{"GET", "/v1/intel-vault/files/2", 403, "denied_path"},
		{"GET", "/v1/parent-organizations/7/environments", 200, "completed"},
		{"POST", "/users-organizations", 403, "read_only_path"},
		{"PATCH", "/v1/users-organizations/users/2", 403, "read_only_path"},
		{"DELETE", "/v1/reports/7", 403, "read_only_path"},
		{"GET", "/users-organizations", 200, "completed"},
		{"GET", "/v1/reports/7", 200, "completed"},
		{"POST", "/v1/cases", 200, "completed"},
	} {
		calls := f.apiCalls.Load()
		resp, _ := f.do(t, tc.method, "https://api.example.com"+tc.path, bearerPlaceholder)
		forwarded := f.apiCalls.Load() != calls
		if resp == nil || resp.StatusCode != tc.status || f.audit.last().Outcome != tc.outcome || forwarded != (tc.status == 200) {
			t.Errorf("%s %s: %v %q forwarded=%v", tc.method, tc.path, resp, f.audit.last().Outcome, forwarded)
		}
	}
}

// The per-Pod proxy rate limit (default 20 requests a second, a burst of
// 200 and 64 in flight per Pod and entry) applies to browser sessions.
func TestBrowserRateLimited(t *testing.T) {
	f := newBrowserFixture(t)
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	proxyTier := cfg.Tiers[ratelimit.TierProxy]
	proxyTier.Rate, proxyTier.Burst = 0.001, 2
	cfg.Tiers[ratelimit.TierProxy] = proxyTier
	f.proxy.rateLimit = ratelimit.New(cfg)
	for i := 0; i < 2; i++ {
		if resp, _ := f.do(t, "GET", "https://api.example.com/v1/cases", bearerPlaceholder); resp == nil || resp.StatusCode != 200 {
			t.Fatalf("request %d: %v", i, resp)
		}
	}
	calls := f.apiCalls.Load()
	if resp, _ := f.do(t, "GET", "https://api.example.com/v1/cases", bearerPlaceholder); resp == nil || resp.StatusCode != http.StatusTooManyRequests ||
		f.audit.last().Outcome != "rate_limited" || f.apiCalls.Load() != calls {
		t.Fatalf("over the limit: %v %q", resp, f.audit.last().Outcome)
	}
}

// Through the proxy, 20 concurrent workers against a failing sign-in make
// one attempt, and the next request inside the minute makes none.
func TestBrowserFailedSignInIsCapped(t *testing.T) {
	f := newBrowserFixtureWith(t, true, nil)
	f.loginErr.Store(true)
	var wg sync.WaitGroup
	var unavailable atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequest("GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil)
			resp, err := f.client.Do(r)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusServiceUnavailable {
				unavailable.Add(1)
			}
		}()
	}
	wg.Wait()
	if f.logins.Load() != 1 || unavailable.Load() != 20 {
		t.Fatalf("%d sign-ins, %d answered 503", f.logins.Load(), unavailable.Load())
	}
	f.loginErr.Store(false)
	if resp, _ := f.do(t, "GET", "https://api.example.com"+httpcatalog.BrowserSeedPath, nil); resp == nil || resp.StatusCode != http.StatusServiceUnavailable || f.logins.Load() != 1 {
		t.Fatalf("inside the minute: %v, %d sign-ins", resp, f.logins.Load())
	}
}

// A web app's hosts get leaves from the browser CA, so a browser pinning that
// CA trusts Gatehouse for them alone; the SNI must name the CONNECT host.
func TestBrowserHostsGetBrowserCALeaves(t *testing.T) {
	f := newBrowserFixture(t)
	for _, target := range []string{"https://app.example.com/index.html", "https://api.example.com" + httpcatalog.BrowserSeedPath} {
		resp, err := f.client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		chain := resp.TLS.PeerCertificates
		if len(chain) != 3 || chain[0].Issuer.CommonName != ca.BrowserCommonName || chain[1].Subject.CommonName != ca.BrowserCommonName {
			t.Fatalf("%s: leaf issuer %q, chain length %d", target, chain[0].Issuer.CommonName, len(chain))
		}
	}
	transport := f.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "other.example.com"
	t.Cleanup(transport.CloseIdleConnections)
	if resp, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://api.example.com" + httpcatalog.BrowserSeedPath); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a browser host served a leaf for a different SNI")
	}
}

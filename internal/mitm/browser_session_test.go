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
	"fmt"
	"io"
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
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const browserPlaceholder = "__vault_STAGING_APP__"

// Synthetic test-user secrets; never real credentials.
type browserVault struct{}

func (browserVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{
		"email": "qa-user@example.test", "password": "synthetic-password-9c1",
		"client_id": "synthetic-confidential-client", "client_secret": "synthetic-client-secret-4f2"},
		"metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

type browserFixture struct {
	client   *http.Client
	audit    *adapterAudit
	sessions *scopeResolver
	logins   atomic.Int32
	mu       sync.Mutex
	seen     map[string]http.Header // last request headers per host
	apiCalls atomic.Int32
	reject   atomic.Int32  // status the API answers with, when set
	refusal  atomic.Value  // WWW-Authenticate on a refusal, when set
	clock    atomic.Int64  // nanoseconds the token cache's clock runs ahead
}

func (f *browserFixture) headers(host string) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[host]
}

// One TLS server plays the app, its API and Auth0, told apart by Host.
func newBrowserFixture(t *testing.T) *browserFixture {
	t.Helper()
	f := &browserFixture{audit: &adapterAudit{}, seen: map[string]http.Header{}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"},
		DNSNames: []string{"app.example.com", "api.example.com", "auth.example.com"}, NotBefore: time.Now().Add(-time.Hour),
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
			f.logins.Add(1)
			claims, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": "org_synthetic", "email": "qa-user@example.test", "nonce": "n"})
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("synthetic-real-access-token-%d", f.logins.Load()),
				"id_token": "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".sig", "expires_in": 3600, "token_type": "Bearer"})
		case "app.example.com":
			w.Header().Set("Set-Cookie", "app_session=synthetic-app-session; Secure")
			fmt.Fprint(w, "<html>app</html>")
		case "api.example.com":
			f.apiCalls.Add(1)
			want := fmt.Sprintf("Bearer synthetic-real-access-token-%d", f.logins.Load())
			if status := f.reject.Load(); status != 0 {
				if challenge, _ := f.refusal.Load().(string); challenge != "" {
					w.Header().Set("WWW-Authenticate", challenge)
				}
				w.WriteHeader(int(status))
				return
			}
			if r.Header.Get("Authorization") != want {
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
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[{"name":"staging-app","kind":"browser-session","host":"api.example.com",
		"placeholder":"` + browserPlaceholder + `","pools":["database-developers"],"browserSession":{"appHost":"app.example.com",
		"auth0":{"domain":"auth.example.com","clientID":"spaClient1","audience":"https://api.example.com","realm":"Username-Password-Authentication",
		"tokenClient":{"mount":"gatehouse","path":"browser/client"}},"user":{"mount":"gatehouse","path":"browser/qa-user"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	authClient := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: upstreamRoots}}}
	tokens := &httpcatalog.Auth0Tokens{Keys: &httpcatalog.Keys{Vault: browserVault{}}, Client: authClient,
		Now: func() time.Time { return time.Now().Add(time.Duration(f.clock.Load())) }}
	f.sessions = &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "database-developers",
		WorkloadID: "pod-uid-1", VaultRole: "proxy", NotAfter: time.Now().Add(30 * time.Minute).Truncate(time.Second)}}
	proxyURL, roots, p := setupProxy(t, f.sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: "unused"}, Audit: f.audit, BrowserTokens: tokens}
	})
	p.upstream.TLSClientConfig.RootCAs = upstreamRoots
	p.upstream.DialContext = dial
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
	for _, secret := range []string{"synthetic-real-access-token", "synthetic-password", "synthetic-client-secret", "synthetic-api-session", "synthetic-app-session"} {
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

package mitm

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
)

const strictCanary = "strict-canary-private-4a8279e6"

type faultAudit struct {
	sink                  requestlog.Durable
	failBegin, failFinish atomic.Bool
}

func (a *faultAudit) Begin(ctx context.Context, r requestlog.Attempt) (string, error) {
	if a.failBegin.Load() {
		return "", errors.New("injected error")
	}
	return a.sink.Begin(ctx, r)
}
func (a *faultAudit) Finish(ctx context.Context, id string, o requestlog.Outcome) error {
	if a.failFinish.Load() {
		return errors.New("injected error")
	}
	return a.sink.Finish(ctx, id, o)
}

type strictFixture struct {
	client   *http.Client
	upstream *httptest.Server
	proxy    *Proxy
	audit    *faultAudit
	store    *store.SQLStore
	calls    atomic.Int64
	proxyURL *url.URL
}

func newStrictFixture(t *testing.T, options ...func(*Options)) *strictFixture {
	t.Helper()
	f := &strictFixture{}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+strictCanary || r.Header.Get("Proxy-Authorization") != "" {
			http.Error(w, "credential check failed", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/echo-body":
			io.WriteString(w, strictCanary)
		case "/echo-header":
			w.Header().Set("X-Echo", strictCanary)
			io.WriteString(w, "ok")
		case "/echo-encoded":
			io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(strictCanary)))
		case "/echo-trailer":
			w.Header().Set("Trailer", "X-Echo")
			w.WriteHeader(200)
			io.WriteString(w, "ok")
			w.Header().Set("X-Echo", strictCanary)
		case "/redirect":
			w.Header().Set("Location", f.upstream.URL+"/ok")
			w.WriteHeader(302)
		case "/upgrade":
			w.Header().Set("Upgrade", "websocket")
			w.WriteHeader(101)
		case "/compressed":
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, "compressed")
		case "/large":
			io.WriteString(w, strings.Repeat("x", strictResponseLimit+1))
		case "/unauthorized":
			w.WriteHeader(401)
		default:
			io.WriteString(w, "approved-output")
		}
	}))
	t.Cleanup(f.upstream.Close)
	var err error
	f.store, err = store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.audit = &faultAudit{sink: requestlog.NewDurable(f.store)}
	u, _ := url.Parse(f.upstream.URL)
	host := u.Hostname()
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host, CredentialKeys: []string{"API_KEY"}, Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "__vault_API_KEY__", Value: strictCanary, In: []string{"header"}}}}}}}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", VaultName: "default", AgentID: "agent-1", WorkloadID: "pod-1", VaultRole: "proxy"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), cp, func(o *Options) {
		o.StrictCredentialProxy = true
		o.DurableAudit = f.audit
		for _, option := range options {
			option(o)
		}
	})
	f.proxy = p
	f.proxyURL = proxyURL
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(f.upstream.Certificate())
	p.upstream.TLSClientConfig.RootCAs = upstreamRoots
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

type strictResponse struct {
	StatusCode int
	Header     http.Header
}

func (f *strictFixture) send(t *testing.T, path string, mutate func(*http.Request)) (strictResponse, string) {
	t.Helper()
	r, err := http.NewRequest("GET", f.upstream.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer __vault_API_KEY__")
	if mutate != nil {
		mutate(r)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), strictCanary) || strings.Contains(resp.Header.Get("X-Echo"), strictCanary) {
		t.Fatal("secret escaped response")
	}
	return strictResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}, string(data)
}
func (f *strictFixture) positive(t *testing.T) {
	t.Helper()
	before := f.calls.Load()
	resp, body := f.send(t, "/ok", nil)
	if resp.StatusCode != 200 || body != "approved-output" || f.calls.Load() != before+1 {
		t.Fatalf("positive control status %d calls %d", resp.StatusCode, f.calls.Load()-before)
	}
	r, err := f.store.GetProxyAudit(context.Background(), resp.Header.Get("X-Request-Id"))
	if err != nil || r.Outcome != "completed" || r.ActorID != "agent-1" || r.WorkloadID != "pod-1" || len(r.MappingIDs) != 1 {
		t.Fatalf("audit: %+v %v", r, err)
	}
}

func TestStrictCredentialProxyDeniesUnsupportedBeforeOutbound(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	tests := []struct {
		name, path string
		mutate     func(*http.Request)
	}{
		{name: "query", path: "/ok?key=__vault_API_KEY__"},
		{name: "ordinary-query", path: "/ok?page=1"},
		{name: "path", path: "/__vault_API_KEY__"},
		{name: "encoded-path", path: "/%5f%5fvault_API_KEY%5f%5f"},
		{name: "double-encoded-path", path: "/%255f%255fvault_API_KEY%255f%255f"},
		{name: "header-name", mutate: func(r *http.Request) { r.Header.Set("__vault_UNKNOWN__", "value") }},
		{name: "unknown", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer __vault_UNKNOWN__") }},
		{name: "malformed", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer __vault_API_KEY_") }},
		{name: "mixed", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer __vault_API_KEY____vault_UNKNOWN__") }},
		{name: "duplicate", mutate: func(r *http.Request) { r.Header.Add("Authorization", "Bearer __vault_API_KEY__") }},
		{name: "unapproved-header", mutate: func(r *http.Request) { r.Header.Set("X-Other", "__vault_API_KEY__") }},
		{name: "missing", mutate: func(r *http.Request) { r.Header.Del("Authorization") }},
		{name: "body", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("__vault_API_KEY__"))
			r.ContentLength = int64(len("__vault_API_KEY__"))
		}},
		{name: "post", mutate: func(r *http.Request) { r.Method = "POST" }},
		{name: "encoding", mutate: func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{name: "upgrade", mutate: func(r *http.Request) { r.Header.Set("Connection", "Upgrade"); r.Header.Set("Upgrade", "websocket") }},
		{name: "host-change", mutate: func(r *http.Request) { r.Host = "other.example.test" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := f.calls.Load()
			path := tc.path
			if path == "" {
				path = "/ok"
			}
			resp, _ := f.send(t, path, tc.mutate)
			if resp.StatusCode != 400 || f.calls.Load() != before {
				t.Fatalf("status %d outbound delta %d", resp.StatusCode, f.calls.Load()-before)
			}
			r, err := f.store.GetProxyAudit(context.Background(), resp.Header.Get("X-Request-Id"))
			if err != nil || r.Decision != "deny" || r.Outcome != "denied" {
				t.Fatalf("denial audit: %+v %v", r, err)
			}
		})
	}
	f.positive(t)
}

func TestStrictCredentialProxyBlocksResponseExposureAndRedirects(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	for _, path := range []string{"/echo-body", "/echo-header", "/echo-encoded", "/echo-trailer", "/redirect", "/upgrade", "/compressed", "/large"} {
		t.Run(path, func(t *testing.T) {
			before := f.calls.Load()
			resp, body := f.send(t, path, nil)
			if resp.StatusCode != 502 || f.calls.Load() != before+1 {
				t.Fatalf("status %d outbound delta %d", resp.StatusCode, f.calls.Load()-before)
			}
			if strings.Contains(body, "approved-output") {
				t.Fatal("redirect followed")
			}
		})
	}
	before := f.calls.Load()
	resp, _ := f.send(t, "/unauthorized", nil)
	if resp.StatusCode != 401 || f.calls.Load() != before+1 {
		t.Fatalf("upstream authentication failure replayed: %d calls", f.calls.Load()-before)
	}
}

func TestStrictCredentialProxyAuditOutageAndUnknownOutcome(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	before := f.calls.Load()
	f.audit.failBegin.Store(true)
	resp, _ := f.send(t, "/ok", nil)
	if resp.StatusCode != 503 || f.calls.Load() != before {
		t.Fatalf("audit outage forwarded: %d %d", resp.StatusCode, f.calls.Load()-before)
	}
	f.audit.failBegin.Store(false)
	f.positive(t)
	before = f.calls.Load()
	f.audit.failFinish.Store(true)
	resp, _ = f.send(t, "/ok", nil)
	if resp.StatusCode != 503 || f.calls.Load() != before+1 {
		t.Fatalf("outcome failure: %d calls %d", resp.StatusCode, f.calls.Load()-before)
	}
	r, err := f.store.GetProxyAudit(context.Background(), resp.Header.Get("X-Request-Id"))
	if err != nil || r.Outcome != "unknown" || r.Status != 0 {
		t.Fatalf("unknown outcome: %+v %v", r, err)
	}
	f.audit.failFinish.Store(false)
	f.positive(t)
}

func TestStrictCredentialProxyPlaintextDenied(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	var calls atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer plain.Close()
	r, _ := http.NewRequest("GET", plain.URL+"/", nil)
	r.Header.Set("Authorization", "Bearer __vault_API_KEY__")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 || calls.Load() != 0 {
		t.Fatalf("plaintext forwarded: %d %d", resp.StatusCode, calls.Load())
	}
}

func TestStrictCredentialProxyUnmatchedAndPassthroughDenied(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	// Request handlers invoke credentials before opening any upstream connection.
	// Change the provider between requests, with each prior request fully finished.
	f.proxy.creds = &fakeCredProvider{byHost: map[string]fakeInjectResult{}}
	before := f.calls.Load()
	resp, _ := f.send(t, "/ok", nil)
	if resp.StatusCode != 403 || f.calls.Load() != before {
		t.Fatal("unmatched request forwarded")
	}
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(f.upstream.URL, "https://"))
	f.proxy.creds = &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{Passthrough: true}}}}
	resp, _ = f.send(t, "/ok", nil)
	if resp.StatusCode != 403 || f.calls.Load() != before {
		t.Fatal("passthrough request forwarded")
	}
}

func TestStrictCredentialProxyRejectsUnsafeMapping(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(f.upstream.URL, "https://"))
	for _, tc := range []struct {
		name   string
		result *brokercore.InjectResult
		err    error
	}{
		{name: "vault-unavailable", err: errors.New("error carrying " + strictCanary)},
		{name: "generic-injection", result: &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host, Headers: map[string]string{"Authorization": "Bearer " + strictCanary}}},
		{name: "body-mapping", result: &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host, CredentialKeys: []string{"API_KEY"}, Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "__vault_API_KEY__", Value: strictCanary, In: []string{"body"}}}}},
		{name: "empty-secret", result: &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host, CredentialKeys: []string{"API_KEY"}, Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "__vault_API_KEY__", In: []string{"header"}}}}},
		{name: "newline-secret", result: &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host, CredentialKeys: []string{"API_KEY"}, Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "__vault_API_KEY__", Value: strictCanary + "\r\nInjected: yes", In: []string{"header"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.proxy.creds = &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: tc.result, err: tc.err}}}
			before := f.calls.Load()
			resp, _ := f.send(t, "/ok", nil)
			if resp.StatusCode < 400 || f.calls.Load() != before {
				t.Fatalf("invalid mapping forwarded: %d delta %d", resp.StatusCode, f.calls.Load()-before)
			}
		})
	}
}

func TestStrictCredentialProxyMissingAuditFailsClosed(t *testing.T) {
	f := newStrictFixture(t)
	f.positive(t)
	f.proxy.durableAudit = nil
	before := f.calls.Load()
	resp, _ := f.send(t, "/ok", nil)
	if resp.StatusCode != 503 || f.calls.Load() != before {
		t.Fatalf("missing audit admitted: %d delta %d", resp.StatusCode, f.calls.Load()-before)
	}
}

func TestStrictCredentialProxyTunnelCapacityAndRelease(t *testing.T) {
	f := newStrictFixture(t, func(o *Options) { o.MaxCredentialProxyTunnels = 1 })
	f.positive(t)
	before := f.calls.Load()
	u, _ := url.Parse(f.upstream.URL)
	conn := dialProxy(t, f.proxyURL)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.Close()
	resp := writeRawRequestLine(t, conn, "CONNECT "+u.Host+" HTTP/1.1", map[string]string{"Host": u.Host, "Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("workload-token:"))})
	defer func() { _ = resp.Body.Close() }()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || f.calls.Load() != before {
		t.Fatalf("tunnel capacity status %d outbound delta %d", resp.StatusCode, f.calls.Load()-before)
	}
	row, err := f.store.GetProxyAudit(context.Background(), resp.Header.Get("X-Request-Id"))
	if err != nil || row.Outcome != "denied" || row.Status != 429 || row.ActorID != "" {
		t.Fatalf("overload audit: %+v %v", row, err)
	}
	f.audit.failBegin.Store(true)
	deniedConn := dialProxy(t, f.proxyURL)
	defer deniedConn.Close()
	failed := writeRawRequestLine(t, deniedConn, "CONNECT "+u.Host+" HTTP/1.1", map[string]string{"Host": u.Host})
	failed.Body.Close()
	if failed.StatusCode != 503 || f.calls.Load() != before {
		t.Fatal("overload audit failure did not deny")
	}
	f.audit.failBegin.Store(false)
	f.client.CloseIdleConnections()
	deadline := time.Now().Add(3 * time.Second)
	for len(f.proxy.strictTunnels) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.proxy.strictTunnels) != 0 {
		t.Fatal("closed tunnel retained capacity")
	}
	f.positive(t)
}

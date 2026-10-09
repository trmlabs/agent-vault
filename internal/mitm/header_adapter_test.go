package mitm

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// Synthetic vendor keys; never real credentials.
const (
	adapterKeyV1 = "sk-synthetic-adapter-key-v1-7f3a91"
	adapterKeyV2 = "sk-synthetic-adapter-key-v2-c04e5d"
)

type adapterAudit struct {
	mu       sync.Mutex
	events   []auditchain.Event
	admitErr error
}

func (a *adapterAudit) Admit() error { a.mu.Lock(); defer a.mu.Unlock(); return a.admitErr }

// Record refuses what the real chain refuses, so a row the chain would reject
// fails here too.
func (a *adapterAudit) Record(e auditchain.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}
func (a *adapterAudit) last() auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return auditchain.Event{}
	}
	return a.events[len(a.events)-1]
}
func (a *adapterAudit) all() []auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditchain.Event(nil), a.events...)
}

type adapterKeys struct {
	mu          sync.Mutex
	value       string
	err         error
	invalidated int
}

func (k *adapterKeys) Get(context.Context, httpcatalog.KeyRef) (httpcatalog.Secret, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return httpcatalog.Secret{}, k.err
	}
	return testSecret(k.value), nil
}
func (k *adapterKeys) Invalidate(httpcatalog.KeyRef) { k.mu.Lock(); k.invalidated++; k.mu.Unlock() }

// testSecret builds a Secret through the public catalog cache with a fake Vault.
func testSecret(value string) httpcatalog.Secret {
	keys := &httpcatalog.Keys{Vault: staticVault(value)}
	s, err := keys.Get(context.Background(), httpcatalog.KeyRef{Mount: "gatehouse", Path: "vendor", Field: "key"})
	if err != nil {
		panic(err)
	}
	return s
}

type adapterFixture struct {
	vendor   *httptest.Server
	port     int
	calls    atomic.Int32
	keys     *adapterKeys
	audit    *adapterAudit
	client   *http.Client
	proxy    *Proxy
	acceptsV string
	seen     atomic.Value // http.Header of the last vendor request
	release  chan struct{}
	sessions *scopeResolver
	proxyURL *url.URL
	roots    *x509.CertPool
}

// scopeResolver lets a test change the admitted scope without touching the
// running proxy.
type scopeResolver struct {
	mu      sync.Mutex
	scope   *brokercore.ProxyScope
	expired bool // every later resolution fails, as for an expired session
}

func (s *scopeResolver) ResolveForProxy(_ context.Context, token, _ string) (*brokercore.ProxyScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "workload-token" || s.expired {
		return nil, brokercore.ErrInvalidSession
	}
	return s.scope, nil
}

func (s *scopeResolver) set(scope *brokercore.ProxyScope) {
	s.mu.Lock()
	s.scope = scope
	s.mu.Unlock()
}

func newAdapterFixture(t *testing.T, options ...func(*Options)) *adapterFixture {
	t.Helper()
	return newAdapterFixtureWith(t, false, options...)
}

// basicKey is how a vendor expecting the key as a Basic user name sees it.
func basicKey(key string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(key+":"))
}

// newAdapterFixtureWith builds the fixture with a Bearer entry, or with basic
// set, an entry whose vendor takes the key as an HTTP Basic user name.
func newAdapterFixtureWith(t *testing.T, basic bool, options ...func(*Options)) *adapterFixture {
	t.Helper()
	f := &adapterFixture{keys: &adapterKeys{value: adapterKeyV1}, audit: &adapterAudit{}, acceptsV: adapterKeyV1, release: make(chan struct{})}
	f.vendor = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.seen.Store(r.Header.Clone())
		want := "Bearer " + f.acceptsV
		if basic {
			want = basicKey(f.acceptsV)
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"method":%q,"bytes":%d}`, r.Method, len(body)) // #nosec G705 -- test upstream; JSON response
		case "/v1/chat/slow":
			time.Sleep(30 * time.Millisecond)
			fmt.Fprint(w, "ok")
		case "/v1/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-f.release
			fmt.Fprint(w, "data: second\n\n")
		case "/v1/echo-split":
			w.Header().Set("Content-Type", "text/plain")
			half := len(adapterKeyV1) / 2
			fmt.Fprint(w, strings.Repeat("a", 40000)+adapterKeyV1[:half])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			fmt.Fprint(w, adapterKeyV1[half:]+"tail")
		case "/v1/echo-header":
			w.Header().Set("X-Debug", "Bearer "+adapterKeyV1)
			fmt.Fprint(w, "ok")
		case "/v1/echo-basic":
			fmt.Fprint(w, strings.TrimPrefix(basicKey(adapterKeyV1), "Basic "))
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	t.Cleanup(f.vendor.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(f.vendor.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	scheme := `"scheme":"Bearer"`
	if basic {
		scheme = `"basicUser":true`
	}
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{
		"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1/chat","/v1/stream","/v1/echo-split","/v1/echo-header","/v1/echo-basic"],
		"methods":["POST","GET"],"header":"Authorization",%s,"placeholder":"__vault_LLM_KEY__",
		"key":{"mount":"gatehouse","path":"vendors/llm","field":"key"},"pools":["pool-agent"],"forwardHeaders":["OpenAI-Beta"]}]}`, f.port, scheme)))
	if err != nil {
		t.Fatal(err)
	}
	f.sessions = &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	proxyURL, roots, p := setupProxy(t, f.sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: f.keys, Audit: f.audit}
		for _, option := range options {
			option(o)
		}
	})
	f.proxy, f.proxyURL, f.roots = p, proxyURL, roots
	vendorRoots := x509.NewCertPool()
	vendorRoots.AddCert(f.vendor.Certificate())
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	vendorAddr := strings.TrimPrefix(f.vendor.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendorAddr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func (f *adapterFixture) url(path string) string {
	return "https://example.com:" + strconv.Itoa(f.port) + path
}

func (f *adapterFixture) do(t *testing.T, method, path, body string, mutate func(*http.Request)) (int, string, error) {
	t.Helper()
	r, err := http.NewRequest(method, f.url(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	if mutate != nil {
		mutate(r)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(resp.Body)
	for _, key := range []string{adapterKeyV1, adapterKeyV2, basicKey(adapterKeyV1)[6:], basicKey(adapterKeyV2)[6:]} {
		if strings.Contains(string(data), key) || strings.Contains(fmt.Sprint(resp.Header), key) {
			t.Fatal("key reached the worker")
		}
	}
	return resp.StatusCode, string(data), readErr
}

// A worker holding only a placeholder, or nothing, gets a POST through with
// the real key added at the broker, and each call leaves admitted and
// completed rows naming the pool, Pod and binding.
func TestAdapterInjectsKeyForPlaceholderOrOmittedHeader(t *testing.T) {
	f := newAdapterFixture(t)
	for _, mutate := range []func(*http.Request){nil, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{"model":"m","messages":[]}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":27}` {
			t.Fatalf("chat: %d %q %v", code, body, err)
		}
	}
	events := f.audit.all()
	if len(events) != 4 || events[0].Event != auditchain.EventHTTPRequest || events[1].Event != auditchain.EventHTTPResponse || events[1].Status != 200 || events[1].Outcome != "completed" {
		t.Fatalf("audit: %+v", events)
	}
	for _, e := range events {
		if e.Pool != "pool-agent" || e.Agent != "agent-uuid-1" || e.PodUID != "pod-uid-1" || e.Binding != "llm" || e.Method != "POST" || e.Session == "" {
			t.Fatalf("attribution: %+v", e)
		}
		if e.Target != "" {
			t.Fatalf("an admitted call carries a target: %+v", e)
		}
	}
}

// A response row records how long the call took from admission, and the
// admitted row carries no duration.
func TestAdapterRecordsResponseDuration(t *testing.T) {
	f := newAdapterFixture(t)
	if code, body, err := f.do(t, "GET", "/v1/chat/slow", "", nil); err != nil || code != 200 || body != "ok" {
		t.Fatalf("slow call: %d %q %v", code, body, err)
	}
	events := f.audit.all()
	if len(events) != 2 || events[0].Event != auditchain.EventHTTPRequest || events[0].Duration != 0 {
		t.Fatalf("admitted row: %+v", events)
	}
	if done := events[1]; done.Event != auditchain.EventHTTPResponse || done.Outcome != "completed" || done.Duration < 30 || done.Duration > 10_000 {
		t.Fatalf("response row: %+v", done)
	}
}

// A refusal inside an open tunnel records the tunnel's CONNECT target, the
// host the broker checked, not the Host header the client sent.
func TestTunnelRefusalRecordsConnectTarget(t *testing.T) {
	f := newAdapterFixture(t)
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err != nil || code != 200 {
		t.Fatalf("open tunnel: %d %v", code, err)
	}
	f.sessions.mu.Lock()
	f.sessions.expired = true
	f.sessions.mu.Unlock()
	code, _, err := f.do(t, "GET", "/v1/chat/x", "", func(r *http.Request) { r.Host = "other.example.net" })
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("in-tunnel refusal: %d %v", code, err)
	}
	if e, want := f.audit.last(), "example.com:"+strconv.Itoa(f.port); e.Event != auditchain.EventDenied || e.Target != want {
		t.Fatalf("refusal row %+v, want target %q", e, want)
	}
}

func TestAdapterRefusesOutsideTheCatalog(t *testing.T) {
	f := newAdapterFixture(t)
	for _, tc := range []struct {
		name, method, path, outcome string
		code                        int
	}{
		{"unlisted path", "POST", "/v1/admin", "unlisted", 403},
		{"prefix is not a segment", "POST", "/v1/chatx", "unlisted", 403},
		{"method", "DELETE", "/v1/chat/completions", "method", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, err := f.do(t, tc.method, tc.path, "", nil)
			if err != nil || code != tc.code || f.audit.last().Outcome != tc.outcome || f.calls.Load() != 0 {
				t.Fatalf("code=%d outcome=%q calls=%d err=%v", code, f.audit.last().Outcome, f.calls.Load(), err)
			}
			if got, want := f.audit.last().Target, "example.com:"+strconv.Itoa(f.port); got != want {
				t.Fatalf("refusal target %q, want %q", got, want)
			}
		})
	}
	// An unlisted host is refused before the tunnel opens.
	r, _ := http.NewRequest("GET", "https://other.example.net:"+strconv.Itoa(f.port)+"/v1/chat", nil)
	resp, err := f.client.Do(r)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err == nil || f.audit.last().Outcome != "unlisted" || f.calls.Load() != 0 {
		t.Fatalf("unlisted host tunnelled: %v %+v", err, f.audit.last())
	}
	if got, want := f.audit.last().Target, "other.example.net:"+strconv.Itoa(f.port); got != want {
		t.Fatalf("unlisted host target %q, want %q", got, want)
	}
	// A pool without the grant is still refused per request inside a tunnel
	// that is already open (this client reuses its earlier tunnel); a new
	// tunnel for it is refused at CONNECT (TestAdapterRefusesAScopeWithoutAPool).
	other := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-9", Pool: "other-pool", WorkloadID: "pod-9"}
	f.sessions.set(other)
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 403 || f.audit.last().Outcome != "pool" || f.calls.Load() != 0 {
		t.Fatalf("ungranted pool: %d %+v", code, f.audit.last())
	}
}

func TestAdapterRejectsMisplacedPlaceholdersAndRoutingHeaders(t *testing.T) {
	f := newAdapterFixture(t)
	for _, tc := range []struct {
		name   string
		path   string
		body   string
		mutate func(*http.Request)
	}{
		{"placeholder in body", "/v1/chat/completions", `{"key":"__vault_LLM_KEY__"}`, nil},
		{"placeholder in query", "/v1/chat/completions?k=__vault_LLM_KEY__", "{}", nil},
		{"placeholder in another header", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("X-Key", "__vault_LLM_KEY__") }},
		{"own credential", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk-worker-supplied") }},
		{"wrong placeholder", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer __vault_OTHER__") }},
		{"traversal", "/v1/chat/../admin", "{}", nil},
		{"encoded traversal", "/v1/chat/..%2Fadmin", "{}", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, err := f.do(t, "POST", tc.path, tc.body, tc.mutate)
			if err != nil || code != 400 || f.calls.Load() != 0 {
				t.Fatalf("code=%d calls=%d err=%v", code, f.calls.Load(), err)
			}
		})
	}
	code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", func(r *http.Request) {
		r.Header.Set("X-HTTP-Method-Override", "DELETE")
		r.Header.Set("X-Forwarded-Host", "evil.example.net")
		r.Header.Set("Cookie", "session=worker")
		r.Header.Set("OpenAI-Beta", "assistants=v2")
	})
	seen, _ := f.seen.Load().(http.Header)
	if err != nil || code != 200 || seen.Get("X-Http-Method-Override") != "" || seen.Get("X-Forwarded-Host") != "" || seen.Get("Cookie") != "" || seen.Get("Openai-Beta") != "assistants=v2" {
		t.Fatalf("header policy: %d %v", code, seen)
	}
}

// A vendor that takes the key as a Basic user name (axios auth.username,
// curl -u key:) gets it that way. The worker sends the placeholder encoded the
// same way, or nothing; the bare placeholder or its own key is refused, and an
// echo of the encoded key is cut off.
func TestAdapterSendsKeyAsBasicUser(t *testing.T) {
	f := newAdapterFixtureWith(t, true)
	placeholder := func(r *http.Request) { r.Header.Set("Authorization", basicKey("__vault_LLM_KEY__")) }
	for _, mutate := range []func(*http.Request){placeholder, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":2}` {
			t.Fatalf("basic: %d %q %v", code, body, err)
		}
	}
	for name, value := range map[string]string{
		"bare placeholder": "Basic __vault_LLM_KEY__",
		"bearer":           "Bearer __vault_LLM_KEY__",
		"own key":          basicKey("sk-worker-own-key"),
		"with password":    "Basic " + base64.StdEncoding.EncodeToString([]byte("__vault_LLM_KEY__:x")),
	} {
		calls := f.calls.Load()
		code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, func(r *http.Request) { r.Header.Set("Authorization", value) })
		if code != 400 || f.calls.Load() != calls || f.audit.last().Outcome != "credential_header" {
			t.Fatalf("%s: %d %+v", name, code, f.audit.last())
		}
	}
	f.do(t, "GET", "/v1/echo-basic", "", placeholder)
	if got := f.audit.last(); got.Event != auditchain.EventHTTPResponse || got.Outcome != "secret_echo" {
		t.Fatalf("encoded key echo: %+v", got)
	}
}

// The key never reaches the worker, even split across two writes of a
// streamed body: the broker aborts before releasing the first half.
func TestAdapterBlocksKeyEchoes(t *testing.T) {
	f := newAdapterFixture(t)
	code, body, err := f.do(t, "GET", "/v1/echo-split", "", nil)
	if err == nil && code == 200 && !strings.Contains(body, "tail") {
		t.Fatalf("expected an aborted stream, got %d", code)
	}
	if err == nil && strings.Contains(body, "tail") {
		t.Fatal("echoing stream completed")
	}
	if strings.Contains(body, adapterKeyV1[:len(adapterKeyV1)/2]) {
		t.Fatal("first half of the key released before screening")
	}
	if got := f.audit.last(); got.Event != auditchain.EventHTTPResponse || got.Outcome != "secret_echo" {
		t.Fatalf("echo outcome: %+v", got)
	}
	if code, _, _ := f.do(t, "GET", "/v1/echo-header", "", nil); code != 502 || f.audit.last().Outcome != "response_refused" {
		t.Fatalf("header echo: %d %+v", code, f.audit.last())
	}
}

// Server-sent events reach the worker as they are produced.
func TestAdapterStreamsServerSentEvents(t *testing.T) {
	f := newAdapterFixture(t)
	r, _ := http.NewRequest("GET", f.url("/v1/stream"), nil)
	r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "data: first\n" {
		t.Fatalf("first event not streamed: %q %v", first, err)
	}
	close(f.release)
	rest, _ := io.ReadAll(reader)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event missing: %q", rest)
	}
}

// After the vendor rejects a rotated-out key, the next request reads the new one.
func TestAdapterRefreshesKeyAfterVendorRejection(t *testing.T) {
	f := newAdapterFixture(t)
	f.acceptsV = adapterKeyV2
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 401 || f.keys.invalidated != 1 {
		t.Fatalf("rejection: %d invalidated=%d", code, f.keys.invalidated)
	}
	f.keys.mu.Lock()
	f.keys.value = adapterKeyV2
	f.keys.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 200 {
		t.Fatalf("rotated key: %d", code)
	}
}

func TestAdapterFailsClosed(t *testing.T) {
	f := newAdapterFixture(t)
	f.audit.mu.Lock()
	f.audit.admitErr = auditchain.ErrCheckpointOverdue
	f.audit.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 503 || f.audit.last().Outcome != "audit_unavailable" {
		t.Fatalf("audit unavailable: %d", code)
	}
	f.audit.mu.Lock()
	f.audit.admitErr = nil
	f.audit.mu.Unlock()
	f.keys.mu.Lock()
	f.keys.err = errors.New("vault sealed")
	f.keys.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 503 || f.audit.last().Outcome != "key_unavailable" {
		t.Fatalf("key unavailable: %d", code)
	}
	if f.calls.Load() != 0 {
		t.Fatal("vendor called while failing closed")
	}
	invalid := &Proxy{adapter: &HeaderAdapter{}}
	rec := httptest.NewRecorder()
	invalid.forwardStrict(rec, httptest.NewRequest("GET", "https://example.com/", nil), "example.com:443", "example.com", 443, true, nil)
	if rec.Code != 503 {
		t.Fatalf("incomplete adapter served: %d", rec.Code)
	}
}

// A verified agent whose scope carries no catalog pool reaches nothing: its
// CONNECT is refused before a tunnel opens.
func TestAdapterRefusesAScopeWithoutAPool(t *testing.T) {
	f := newAdapterFixture(t)
	f.sessions.set(&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", WorkloadID: "pod-uid-1"})
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 0 || f.audit.last().Outcome != "pool" || f.calls.Load() != 0 {
		t.Fatalf("pool-less scope admitted: %d %+v", code, f.audit.last())
	}
}

// Paths some backends normalise differently are refused before the prefix
// match: path parameters and segments that begin with "..".
func TestUnsafePathRefusesTraversalForms(t *testing.T) {
	for path, unsafe := range map[string]bool{
		"/v1/allowed/..;/admin": true,
		"/v1/allowed;x=1":       true,
		"/v1/allowed/..x":       true,
		"/v1/allowed/../admin":  true,
		"/v1/allowed/./x":       true,
		"/v1/allowed/a..b":      false,
		"/v1/allowed/x.json":    false,
	} {
		if got := unsafePath(path); got != unsafe {
			t.Errorf("unsafePath(%q) = %v, want %v", path, got, unsafe)
		}
	}
}

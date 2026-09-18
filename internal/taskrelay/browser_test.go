package taskrelay

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type browserFixture struct {
	relay     *BrowserRelay
	upstream  *httptest.Server
	proofs    []string
	paths     []string
	active    bool
	auditFail string
	response  func(http.ResponseWriter, *http.Request)
}

func newBrowserFixture(t *testing.T) *browserFixture {
	t.Helper()
	f := &browserFixture{active: true}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.paths = append(f.paths, r.URL.Path)
		f.proofs = append(f.proofs, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if f.response != nil {
			f.response(w, r)
			return
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid broker input")
		}
		switch r.URL.Path {
		case "/v1/browser/tasks":
			if body["task"] != "approved-task" || len(body) != 1 {
				t.Errorf("unexpected task fields: %v", body)
			}
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"handle":%q,"expiresAt":%d}`, strings.Repeat("h", 43), time.Now().Add(time.Minute).UnixMilli())
		case "/v1/browser/check":
			if body["handle"] != strings.Repeat("h", 43) || body["action"] != "check-visible" || len(body) != 2 {
				t.Error("unexpected check fields")
			}
			fmt.Fprint(w, `{"matched":true}`)
		case "/v1/browser/close":
			if body["handle"] != strings.Repeat("h", 43) || len(body) != 1 {
				t.Error("unexpected close fields")
			}
			fmt.Fprint(w, `{"closed":true}`)
		default:
			t.Error("unapproved broker path")
		}
	}))
	t.Cleanup(f.upstream.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.upstream.Certificate().Raw})
	n := 0
	var err error
	f.relay, err = NewBrowserRelay(BrowserOptions{Endpoint: f.upstream.URL, CA: cert, Task: "approved-task", Deadline: time.Now().Add(time.Minute), Proof: func(context.Context) (string, error) { n++; return fmt.Sprintf("header.payload%d.signature", n), nil }, Authorize: func(_ context.Context, peer string) error {
		if !f.active || peer != "192.0.2.1:1234" {
			return errors.New("denied")
		}
		return nil
	}, Audit: func(_ context.Context, _ string, outcome string) error {
		if f.auditFail == outcome {
			return errors.New("audit unavailable")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.relay.Close(context.Background()) })
	return f
}

func (f *browserFixture) request(path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.relay.ServeHTTP(w, r)
	return w
}

func TestBrowserRelayLifecycleAndProofRotation(t *testing.T) {
	f := newBrowserFixture(t)
	created := f.request("/v1/browser/tasks", "{}", nil)
	if created.Code != 201 || strings.Contains(created.Body.String(), "handle") || !strings.Contains(created.Body.String(), `"ready":true`) {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	if got := f.request("/v1/browser/tasks", "{}", nil); got.Code != 409 {
		t.Fatal("duplicate create admitted")
	}
	if got := f.request("/v1/browser/check", "{}", nil); got.Code != 200 || got.Body.String() != "{\"matched\":true}\n" {
		t.Fatalf("check: %d %s", got.Code, got.Body.String())
	}
	if got := f.request("/v1/browser/close", "{}", nil); got.Code != 200 {
		t.Fatal("close failed")
	}
	if len(f.paths) != 3 || f.proofs[0] == f.proofs[1] || f.proofs[1] == f.proofs[2] {
		t.Fatal("proof not refreshed per action")
	}
	if got := f.request("/v1/browser/check", "{}", nil); got.Code != 409 {
		t.Fatal("closed task admitted")
	}
}

func TestBrowserRelayRejectsAgentSelectedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		headers          map[string]string
	}{
		{"task", "/v1/browser/tasks", `{"task":"other"}`, nil},
		{"handle", "/v1/browser/check", `{"handle":"other"}`, nil},
		{"query", "/v1/browser/tasks?task=other", "{}", nil},
		{"legacy", "/login", "{}", nil},
		{"auth", "/v1/browser/tasks", "{}", map[string]string{"Authorization": "Bearer attacker"}},
		{"proxy auth", "/v1/browser/tasks", "{}", map[string]string{"Proxy-Authorization": "Bearer attacker"}},
		{"identity", "/v1/browser/tasks", "{}", map[string]string{"X-Forwarded-For": "192.0.2.1"}},
		{"origin", "/v1/browser/tasks", "{}", map[string]string{"Origin": "https://evil.test"}},
		{"encoded body", "/v1/browser/tasks", "{}", map[string]string{"Content-Encoding": "gzip"}},
		{"null", "/v1/browser/tasks", "null", nil},
		{"oversize", "/v1/browser/tasks", strings.Repeat(" ", 2049) + "{}", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBrowserFixture(t)
			got := f.request(tc.path, tc.body, tc.headers)
			if got.Code < 400 || len(f.paths) != 0 {
				t.Fatalf("admitted: %d", got.Code)
			}
		})
	}
}

func TestBrowserRelayWrongPeerCannotCloseExistingTask(t *testing.T) {
	f := newBrowserFixture(t)
	if f.request("/v1/browser/tasks", "{}", nil).Code != 201 {
		t.Fatal("create")
	}
	r := httptest.NewRequest("POST", "/v1/browser/check", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.2:1234"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.relay.ServeHTTP(w, r)
	if w.Code != 403 || len(f.paths) != 1 {
		t.Fatal("crosspair forwarded or disrupted task")
	}
	if f.request("/v1/browser/check", "{}", nil).Code != 200 {
		t.Fatal("legitimate task disrupted")
	}
}

func TestBrowserRelayWithdrawalAfterCreateClosesBeforeDeny(t *testing.T) {
	f := newBrowserFixture(t)
	f.response = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/browser/tasks" {
			f.active = false
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"handle":%q,"expiresAt":%d}`, strings.Repeat("h", 43), time.Now().Add(time.Minute).UnixMilli())
		} else {
			fmt.Fprint(w, `{"closed":true}`)
		}
	}
	got := f.request("/v1/browser/tasks", "{}", nil)
	if got.Code != 403 || len(f.paths) != 2 || f.paths[1] != "/v1/browser/close" || strings.Contains(got.Body.String(), "ready") {
		t.Fatalf("withdrawal not suppressed/closed: %d %v", got.Code, f.paths)
	}
}

func TestBrowserRelayAuditFailure(t *testing.T) {
	for _, outcome := range []string{"attempt", "success"} {
		t.Run(outcome, func(t *testing.T) {
			f := newBrowserFixture(t)
			f.auditFail = outcome
			got := f.request("/v1/browser/tasks", "{}", nil)
			if got.Code != 503 {
				t.Fatalf("status %d", got.Code)
			}
			if outcome == "attempt" && len(f.paths) != 0 {
				t.Fatal("forwarded without audit")
			}
			if outcome == "success" && (len(f.paths) != 2 || f.paths[1] != "/v1/browser/close") {
				t.Fatal("audit failure did not close created browser")
			}
		})
	}
}

func TestBrowserRelayRejectsUnsafeResponsesAndDoesNotRetryUnknownCreate(t *testing.T) {
	for _, name := range []string{"redirect", "cookie", "reflection", "unknown", "duplicate", "null", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f := newBrowserFixture(t)
			f.response = func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "redirect":
					w.Header().Set("Location", f.upstream.URL+"/login")
					w.WriteHeader(302)
				case "cookie":
					w.Header().Set("Set-Cookie", "secret=value")
					w.WriteHeader(201)
					fmt.Fprint(w, `{}`)
				case "reflection":
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(map[string]string{"secret": r.Header.Get("Authorization")})
				case "unknown":
					w.WriteHeader(201)
					fmt.Fprint(w, `{"accessToken":"secret"}`)
				case "duplicate":
					w.WriteHeader(201)
					fmt.Fprint(w, `{"handle":"a","handle":"b","expiresAt":1}`)
				case "null":
					w.WriteHeader(201)
					fmt.Fprint(w, `null`)
				case "oversize":
					w.WriteHeader(201)
					fmt.Fprint(w, strings.Repeat("a", 2049))
				}
			}
			got := f.request("/v1/browser/tasks", "{}", nil)
			if got.Code != 502 || got.Header().Get("Set-Cookie") != "" || strings.Contains(got.Body.String(), "secret") {
				t.Fatalf("unsafe response: %d %s", got.Code, got.Body.String())
			}
			if again := f.request("/v1/browser/tasks", "{}", nil); again.Code != 409 || len(f.paths) != 1 {
				t.Fatal("unknown creation automatically retried")
			}
		})
	}
}

func TestBrowserRelayDeadlineAndSupervisorClose(t *testing.T) {
	f := newBrowserFixture(t)
	if f.request("/v1/browser/tasks", "{}", nil).Code != 201 {
		t.Fatal("create")
	}
	if err := f.relay.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.request("/v1/browser/check", "{}", nil); got.Code != 403 {
		t.Fatal("closed relay admitted")
	}
	g := newBrowserFixture(t)
	g.relay.options.Deadline = time.Now().Add(-time.Second)
	if got := g.request("/v1/browser/tasks", "{}", nil); got.Code != 403 || len(g.paths) != 0 {
		t.Fatal("expired task admitted")
	}
}

func TestBrowserRelayConcurrentActionDeniedAndWithdrawalSuppressesCheck(t *testing.T) {
	f := newBrowserFixture(t)
	if f.request("/v1/browser/tasks", "{}", nil).Code != 201 {
		t.Fatal("create")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f.response = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/browser/check" {
			close(entered)
			<-release
			f.active = false
			fmt.Fprint(w, `{"matched":true}`)
		} else {
			fmt.Fprint(w, `{"closed":true}`)
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.request("/v1/browser/check", "{}", nil) }()
	<-entered
	if got := f.request("/v1/browser/check", "{}", nil); got.Code != 429 {
		t.Fatal("concurrent action admitted")
	}
	close(release)
	got := <-done
	if got.Code != 403 || strings.Contains(got.Body.String(), "matched") || f.paths[len(f.paths)-1] != "/v1/browser/close" {
		t.Fatal("withdrawn check delivered or not cleaned")
	}
}

func TestBrowserRelayDeniesInvalidProofAndWrongMethod(t *testing.T) {
	f := newBrowserFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/browser/tasks", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.relay.ServeHTTP(w, r)
	if w.Code != 400 || len(f.paths) != 0 {
		t.Fatal("GET admitted")
	}
	f.relay.options.Proof = func(context.Context) (string, error) { return "invalid\r\nproof", nil }
	if got := f.request("/v1/browser/tasks", "{}", nil); got.Code != 502 || len(f.paths) != 0 {
		t.Fatal("invalid proof forwarded")
	}
}

func TestBrowserRelayRechecksPairAfterProofRead(t *testing.T) {
	f := newBrowserFixture(t)
	f.relay.options.Proof = func(context.Context) (string, error) { f.active = false; return "header.payload.signature", nil }
	if got := f.request("/v1/browser/tasks", "{}", nil); got.Code != 502 || len(f.paths) != 0 {
		t.Fatal("pair lost during proof read was forwarded")
	}
}

func TestBrowserRelayIgnoresClientAcceptEncoding(t *testing.T) {
	for _, encoding := range []string{"gzip", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			f := newBrowserFixture(t)
			f.response = func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "" {
					t.Error("client encoding forwarded")
				}
				if r.URL.Path == "/v1/browser/close" {
					fmt.Fprint(w, `{"closed":true}`)
					return
				}
				w.WriteHeader(201)
				fmt.Fprintf(w, `{"handle":%q,"expiresAt":%d}`, strings.Repeat("h", 43), time.Now().Add(time.Minute).UnixMilli())
			}
			if got := f.request("/v1/browser/tasks", "{}", map[string]string{"Accept-Encoding": encoding}); got.Code != 201 {
				t.Fatalf("standard client refused: %d", got.Code)
			}
		})
	}
}

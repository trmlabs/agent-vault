package actionref

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each isolated runner owns a handler; one handler admits only one active action.
// The authority below is shared but synthetic. This test does not exercise the
// credential proxy, a real identity provider, or deployed runner isolation.
func TestActorRevocationIsolationAcrossHandlerInstances(t *testing.T) {
	for _, revoke := range []string{"identity", "policy"} {
		t.Run(revoke, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var revoked atomic.Bool
			var callsA, callsB atomic.Int32
			startedA, startedB := make(chan struct{}), make(chan struct{})
			canceledA, canceledB := make(chan struct{}), make(chan struct{})
			recheckedB, releaseB := make(chan struct{}), make(chan struct{})
			var observedB sync.Once
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/a":
					if callsA.Add(1) == 1 {
						close(startedA)
					}
					<-r.Context().Done()
					close(canceledA)
				case "/b":
					if callsB.Add(1) == 1 {
						close(startedB)
					}
					select {
					case <-r.Context().Done():
						close(canceledB)
						return
					case <-releaseB:
						_, _ = io.WriteString(w, `{"result":"approved","secret":"canary"}`)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			// Cancel requests before closing the upstream, including fatal paths.
			defer cancel()
			verify := func(_ context.Context, token string) (Identity, error) {
				if token != "a" && token != "b" {
					return Identity{}, errors.New("unknown identity")
				}
				if token == "a" && revoked.Load() && revoke == "identity" {
					return Identity{}, errors.New("revoked identity")
				}
				return Identity{Actor: token, Run: "run-" + token, Expires: time.Now().Add(time.Minute)}, nil
			}
			allow := func(_ context.Context, id Identity) (bool, error) {
				if id.Actor == "b" && revoked.Load() {
					observedB.Do(func() { close(recheckedB) })
				}
				return id.Actor != "a" || !revoked.Load() || revoke != "policy", nil
			}
			makeHandler := func(actor string) http.Handler {
				t.Helper()
				h, err := New(Config{
					Client: upstream.Client(), Upstream: upstream.URL + "/" + actor,
					Fields: []string{"result"}, Verify: verify, Allow: allow,
					Poll: 10 * time.Millisecond, LookupTimeout: 100 * time.Millisecond,
					MaxDuration: 5 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				return h
			}
			run := func(h http.Handler, actor string) <-chan *httptest.ResponseRecorder {
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					r := httptest.NewRequest(http.MethodPost, "/actions/read", nil).WithContext(ctx)
					r.Header.Set("Authorization", "Bearer "+actor)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					done <- w
				}()
				return done
			}
			waitSignal := func(ch <-chan struct{}, description string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out waiting for %s", description)
				}
			}
			waitResponse := func(ch <-chan *httptest.ResponseRecorder, want int) *httptest.ResponseRecorder {
				t.Helper()
				select {
				case w := <-ch:
					if w.Code != want {
						t.Fatalf("status=%d, want %d; body=%q", w.Code, want, w.Body.String())
					}
					return w
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for action response")
					return nil
				}
			}
			a, b := makeHandler("a"), makeHandler("b")
			doneA, doneB := run(a, "a"), run(b, "b")
			waitSignal(startedA, "actor A upstream work")
			waitSignal(startedB, "actor B upstream work")
			revoked.Store(true)
			waitSignal(canceledA, "actor A upstream cancellation")
			waitResponse(doneA, http.StatusForbidden)
			waitSignal(recheckedB, "actor B authority recheck after A revocation")
			select {
			case <-canceledB:
				t.Fatal("actor A revocation canceled actor B upstream work")
			case w := <-doneB:
				t.Fatalf("actor B action ended before upstream release: %d", w.Code)
			default:
			}
			close(releaseB)
			checkB := func(done <-chan *httptest.ResponseRecorder) {
				t.Helper()
				if w := waitResponse(done, http.StatusOK); w.Body.String() != "{\"result\":\"approved\"}\n" {
					t.Fatalf("actor B output not filtered: %q", w.Body.String())
				}
			}
			checkB(doneB)
			checkB(run(b, "b"))
			wantDenied := http.StatusForbidden
			if revoke == "identity" {
				wantDenied = http.StatusUnauthorized
			}
			waitResponse(run(a, "a"), wantDenied)
			if callsA.Load() != 1 || callsB.Load() != 2 {
				t.Fatalf("upstream calls: A=%d B=%d, want A=1 B=2", callsA.Load(), callsB.Load())
			}
		})
	}
}

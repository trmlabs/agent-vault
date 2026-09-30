package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

func TestRuntimeObserverDisabledByDefault(t *testing.T) {
	s, _, _, _ := setupDatabaseAPITest(t)
	req := httptest.NewRequest("GET", "/v1/runtime/cleanup-status", nil)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	if err := s.EnableCleanupObserver(nil, 14324); err == nil {
		t.Fatal("non-strict broker accepted")
	}
}

func TestRuntimeObserverDoesNotAcceptOwnerSession(t *testing.T) {
	s, _, owner, _ := setupDatabaseAPITest(t)
	called := false
	h, err := runtimestatus.New(func(context.Context, string) error { return errors.New("not observer workload") }, func(context.Context) (runtimestatus.Observation, error) {
		called = true
		return runtimestatus.Observation{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.cleanupObserverServer, err = cleanupObserverHTTPServer(h, 14324)
	if err != nil {
		t.Fatal(err)
	}
	ownerRequest := httptest.NewRequest(http.MethodGet, "/v1/runtime/cleanup-status", nil)
	ownerResponse := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(ownerResponse, ownerRequest)
	if ownerResponse.Code != http.StatusNotFound {
		t.Fatal("owner API exposes cleanup observer")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/cleanup-status", nil)
	req.Header.Set("Authorization", "Bearer "+owner)
	w := httptest.NewRecorder()
	s.cleanupObserverServer.Handler.ServeHTTP(w, req)
	if w.Code != 401 || called {
		t.Fatal("owner session bypassed observer authentication")
	}
}

func TestCleanupListenerExcludesManagementOnColdStore(t *testing.T) {
	// No owner or store is needed: this listener has only the observer handler.
	h, err := runtimestatus.New(func(_ context.Context, proof string) error {
		if proof != "observer-proof" {
			return errors.New("denied")
		}
		return nil
	}, func(context.Context) (runtimestatus.Observation, error) {
		return runtimestatus.Observation{Initialized: true, Healthy: true, Consistent: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	cases := []struct {
		method, path, proof string
		code                int
	}{
		{"POST", "/v1/auth/register", "observer-proof", 404},
		{"POST", "/v1/auth/login", "observer-proof", 404},
		{"GET", "/v1/settings", "observer-proof", 404},
		{"POST", "/v1/database-cleanup/example/confirm", "observer-proof", 404},
		{"GET", "/v1/runtime/cleanup-status", "observer-proof", 200},
		{"GET", "/v1/runtime/cleanup-status", "wrong-proof", 401},
		{"POST", "/v1/runtime/cleanup-status", "observer-proof", 405},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tc.proof)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != tc.code {
			t.Fatalf("%s %s: %d", tc.method, tc.path, res.StatusCode)
		}
	}
}

func TestCleanupListenerLoopbackBindFailureAndShutdown(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	srv, err := cleanupObserverHTTPServer(h, port)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cleanupObserverServer: srv}
	if _, err := s.listenCleanupObserver(); err == nil {
		t.Fatal("occupied observer port accepted")
	}
	_ = occupied.Close()
	ln, err := s.listenCleanupObserver()
	if err != nil {
		t.Fatal(err)
	}
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		t.Fatal("non-loopback observer")
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	res, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond); err == nil {
		t.Fatal("observer listener survived shutdown")
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := cleanupObserverHTTPServer(h, port); err == nil {
			t.Fatal("invalid port accepted")
		}
	}
}

func TestCleanupListenerCancelsActiveRequestOnForcedClose(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(canceled) })
	srv, err := cleanupObserverHTTPServer(h, 14324)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()
	go func() {
		res, err := http.Get("http://" + ln.Addr().String())
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	_ = srv.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request context not canceled")
	}
}

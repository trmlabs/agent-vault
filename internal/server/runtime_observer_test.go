package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
	if err := s.EnableCleanupObserver(nil); err == nil {
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
	s.cleanupObserver = h
	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/cleanup-status", nil)
	req.Header.Set("Authorization", "Bearer "+owner)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != 401 || called {
		t.Fatal("owner session bypassed observer authentication")
	}
}

package runtimestatus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObservationStates(t *testing.T) {
	base := Observation{Initialized: true, Healthy: true, Consistent: true}
	for _, tc := range []struct {
		name   string
		change func(*Observation)
		err    error
		status string
		code   int
	}{
		{"empty", func(*Observation) {}, nil, "ready", 200},
		{"active", func(o *Observation) { o.ActiveConnections = 1 }, nil, "pending", 200},
		{"cleanup", func(o *Observation) { o.UnfinishedCleanup = 1 }, nil, "pending", 200},
		{"unknown issuance", func(o *Observation) { o.UnfinishedCleanup = 1; o.UnknownCleanup = 1 }, nil, "unknown", 503},
		{"not initialized", func(o *Observation) { o.Initialized = false }, nil, "unknown", 503},
		{"authority lost", func(o *Observation) { o.Healthy = false }, nil, "unknown", 503},
		{"admission race", func(o *Observation) { o.Consistent = false }, nil, "unknown", 503},
		{"invalid count", func(o *Observation) { o.ActiveConnections = -1 }, nil, "unknown", 503},
		{"impossible unknown", func(o *Observation) { o.UnknownCleanup = 1 }, nil, "unknown", 503},
		{"journal unavailable", func(*Observation) {}, errors.New("sensitive accessor and password"), "unknown", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := base
			tc.change(&observation)
			h, err := New(func(context.Context, string) error { return nil }, func(context.Context) (Observation, error) { return observation, tc.err })
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/v1/runtime/cleanup-status", nil)
			req.Header.Set("Authorization", "Bearer synthetic-proof")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("code %d", w.Code)
			}
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["status"] != tc.status || len(got) != 6 || got["observedAt"] == "" {
				t.Fatalf("unexpected response %v", got)
			}
			if strings.Contains(w.Body.String(), "sensitive") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unsafe response")
			}
		})
	}
}

func TestUnauthorizedNeverReadsState(t *testing.T) {
	for _, header := range []string{"", "Bearer ", "Basic synthetic", "Bearer one,two", "Bearer " + strings.Repeat("x", 32769), "Bearer denied"} {
		t.Run(header[:min(len(header), 20)], func(t *testing.T) {
			called := false
			h, _ := New(func(context.Context, string) error { return errors.New("denied") }, func(context.Context) (Observation, error) { called = true; return Observation{}, nil })
			req := httptest.NewRequest("GET", "/v1/runtime/cleanup-status", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 401 || called || w.Body.Len() != 0 {
				t.Fatal("unauthorized state disclosure")
			}
		})
	}
}

func TestRejectMutationAndCancelledAuthorization(t *testing.T) {
	for _, method := range []string{"POST", "DELETE", "PUT"} {
		h, _ := New(func(context.Context, string) error { t.Fatal("authorization reached"); return nil }, func(context.Context) (Observation, error) { t.Fatal("snapshot reached"); return Observation{}, nil })
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/v1/runtime/cleanup-status", nil))
		if w.Code != 405 {
			t.Fatal(w.Code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, _ := New(func(context.Context, string) error { cancel(); return nil }, func(context.Context) (Observation, error) { t.Fatal("cancelled read"); return Observation{}, nil })
	req := httptest.NewRequest("GET", "/v1/runtime/cleanup-status", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer synthetic")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code)
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}

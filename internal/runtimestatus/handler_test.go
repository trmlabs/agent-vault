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

func TestProxyGrantsReportedOnlyWhenConfigured(t *testing.T) {
	ready := func(context.Context) (Observation, error) {
		return Observation{Initialized: true, Healthy: true, Consistent: true}, nil
	}
	allow := func(context.Context, string) error { return nil }
	read := func(h http.Handler) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/v1/runtime/cleanup-status", nil)
		req.Header.Set("Authorization", "Bearer proof")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	plain, err := New(allow, ready)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := read(plain)["proxyGrants"]; present {
		t.Fatal("grants reported without a configured check")
	}
	for _, c := range []struct {
		ok   bool
		err  error
		want string
	}{{true, nil, "authorized"}, {false, nil, "missing"}, {true, errors.New("store"), "unknown"}} {
		h, err := New(allow, ready, func(context.Context) (bool, error) { return c.ok, c.err })
		if err != nil {
			t.Fatal(err)
		}
		if got := read(h)["proxyGrants"]; got != c.want {
			t.Fatalf("proxyGrants = %v, want %s", got, c.want)
		}
	}
	if _, err := New(allow, ready, nil); err == nil {
		t.Fatal("nil grants check accepted")
	}
}

func getStatus(t *testing.T, h http.Handler, target string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer synthetic-proof")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, body, rec.Body.String()
}

func agentHandler(t *testing.T, observation Observation, err error) http.Handler {
	t.Helper()
	h, newErr := New(func(context.Context, string) error { return nil }, func(context.Context) (Observation, error) { return observation, err })
	if newErr != nil {
		t.Fatal(newErr)
	}
	return h
}

// Two workers: agent-b's pending and unknown work is broker-wide state, but
// does not block agent-a, and its identifier never reaches agent-a's answer.
func TestAgentStatusGatesOnlyOnItsOwnWork(t *testing.T) {
	h := agentHandler(t, Observation{Initialized: true, Healthy: true, Consistent: true, ActiveConnections: 1, UnfinishedCleanup: 2, UnknownCleanup: 1,
		Actors: map[string]Counts{"agent-b": {ActiveConnections: 1, UnfinishedCleanup: 2, UnknownCleanup: 1}}}, nil)
	code, body, _ := getStatus(t, h, "/v1/runtime/cleanup-status")
	if code != 503 || body["status"] != "unknown" || body["agent"] != nil {
		t.Fatalf("broker-wide answer changed: %d %v", code, body)
	}
	code, body, raw := getStatus(t, h, "/v1/runtime/cleanup-status?agent=agent-a")
	agent, _ := body["agent"].(map[string]any)
	if code != 200 || agent["status"] != "ready" || agent["activeConnections"] != 0.0 || agent["unfinishedCleanup"] != 0.0 || body["status"] != "unknown" {
		t.Fatalf("agent-a blocked by another agent: %d %v", code, body)
	}
	if strings.Contains(raw, "agent-b") || strings.Contains(raw, "agent-a") {
		t.Fatal("agent identifier disclosed")
	}
	code, body, _ = getStatus(t, h, "/v1/runtime/cleanup-status?agent=agent-b")
	agent, _ = body["agent"].(map[string]any)
	if code != 503 || agent["status"] != "unknown" || agent["unknownCleanup"] != 1.0 {
		t.Fatalf("agent-b unknown issuance hidden: %d %v", code, body)
	}
}

// Legacy cleanup records and unauthenticated connections carry no actor, so
// they block every agent, including one the broker has never seen.
func TestAgentStatusCountsUnattributedAgainstEveryAgent(t *testing.T) {
	for _, tc := range []struct {
		name         string
		unattributed Counts
		status       string
		code         int
	}{
		{"connection", Counts{ActiveConnections: 1}, "pending", 200},
		{"legacy record", Counts{UnfinishedCleanup: 1}, "pending", 200},
		{"legacy unknown issuance", Counts{UnfinishedCleanup: 1, UnknownCleanup: 1}, "unknown", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.unattributed
			h := agentHandler(t, Observation{Initialized: true, Healthy: true, Consistent: true, ActiveConnections: u.ActiveConnections, UnfinishedCleanup: u.UnfinishedCleanup, UnknownCleanup: u.UnknownCleanup, Unattributed: u}, nil)
			for _, id := range []string{"agent-a", "never-seen"} {
				code, body, _ := getStatus(t, h, "/v1/runtime/cleanup-status?agent="+id)
				agent, _ := body["agent"].(map[string]any)
				if code != tc.code || agent["status"] != tc.status {
					t.Fatalf("%s: %d %v", id, code, body)
				}
			}
		})
	}
}

// A snapshot that cannot account for every item by actor, or cannot be read at
// all, never yields a per-agent ready.
func TestAgentStatusFailsClosedOnUnpartitionedSnapshot(t *testing.T) {
	healthy := Observation{Initialized: true, Healthy: true, Consistent: true}
	for _, tc := range []struct {
		name        string
		observation Observation
		err         error
	}{
		{"totals without partition", Observation{Initialized: true, Healthy: true, Consistent: true, UnfinishedCleanup: 1}, nil},
		{"partition exceeds totals", Observation{Initialized: true, Healthy: true, Consistent: true, Actors: map[string]Counts{"agent-b": {ActiveConnections: 1}}}, nil},
		{"negative actor count", Observation{Initialized: true, Healthy: true, Consistent: true, ActiveConnections: 0, Actors: map[string]Counts{"agent-b": {ActiveConnections: -1}}, Unattributed: Counts{ActiveConnections: 1}}, nil},
		{"admission race", Observation{Initialized: true, Healthy: true}, nil},
		{"journal unavailable", healthy, errors.New("sensitive accessor")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body, raw := getStatus(t, agentHandler(t, tc.observation, tc.err), "/v1/runtime/cleanup-status?agent=agent-a")
			agent, _ := body["agent"].(map[string]any)
			if code != 503 || agent["status"] != "unknown" || strings.Contains(raw, "sensitive") {
				t.Fatalf("%d %v", code, body)
			}
		})
	}
}

func TestAgentQueryRejectedBeforeReadingState(t *testing.T) {
	for _, query := range []string{"agent=", "agent=a&agent=b", "agent=a&extra=1", "other=a", "agent=a%20b", "agent=a/b", "agent=" + strings.Repeat("a", 129), "agent=%zz"} {
		t.Run(query[:min(len(query), 24)], func(t *testing.T) {
			h, _ := New(func(context.Context, string) error { t.Fatal("authorization reached"); return nil }, func(context.Context) (Observation, error) { t.Fatal("snapshot reached"); return Observation{}, nil })
			req := httptest.NewRequest(http.MethodGet, "/v1/runtime/cleanup-status?"+query, nil)
			req.Header.Set("Authorization", "Bearer synthetic-proof")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 400 || rec.Body.Len() != 0 {
				t.Fatalf("code %d", rec.Code)
			}
		})
	}
}

// The deployed single-worker manager sends no agent parameter. Its response
// keeps exactly the fields and codes it had before attribution, and an agent
// that owns all the work sees the same counts as the totals.
func TestSingleWorkerResponseUnchanged(t *testing.T) {
	for _, tc := range []struct {
		owned  Counts
		status string
		code   int
	}{
		{Counts{}, "ready", 200},
		{Counts{ActiveConnections: 2, UnfinishedCleanup: 1}, "pending", 200},
		{Counts{UnfinishedCleanup: 1, UnknownCleanup: 1}, "unknown", 503},
	} {
		o := Observation{Initialized: true, Healthy: true, Consistent: true, ActiveConnections: tc.owned.ActiveConnections, UnfinishedCleanup: tc.owned.UnfinishedCleanup, UnknownCleanup: tc.owned.UnknownCleanup,
			Actors: map[string]Counts{"only-agent": tc.owned}}
		h := agentHandler(t, o, nil)
		code, body, _ := getStatus(t, h, "/v1/runtime/cleanup-status")
		if code != tc.code || body["status"] != tc.status || len(body) != 6 || body["unfinishedCleanup"] != float64(tc.owned.UnfinishedCleanup) {
			t.Fatalf("legacy response changed: %d %v", code, body)
		}
		code, body, _ = getStatus(t, h, "/v1/runtime/cleanup-status?agent=only-agent")
		agent, _ := body["agent"].(map[string]any)
		if code != tc.code || agent["status"] != tc.status || agent["activeConnections"] != float64(tc.owned.ActiveConnections) || agent["unknownCleanup"] != float64(tc.owned.UnknownCleanup) {
			t.Fatalf("single agent diverged from totals: %d %v", code, body)
		}
	}
}

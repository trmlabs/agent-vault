package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const g1 = "11111111-1111-1111-1111-111111111111"

type fakeSource struct {
	person Person
	err    error
	calls  int
}

func (f *fakeSource) Lookup(_ context.Context, _ string, groups []string) (Person, error) {
	f.calls++
	if f.err != nil {
		return Person{}, f.err
	}
	p := f.person
	p.MemberOf = intersect(groups, f.person.MemberOf)
	return p, nil
}

func TestDecide(t *testing.T) {
	member := &fakeSource{person: Person{ObjectID: "oid", Enabled: true, MemberOf: []string{g1}}}
	t1 := Entry{Tier: "T1", Requires: []string{g1}}
	claude := Pool{Identity: "claude-session", Ceiling: "T1"}
	alice := Requester{Kind: "person", Subject: "sso|alice"}
	cases := []struct {
		name    string
		source  Source
		pool    Pool
		entry   Entry
		who     Requester
		allowed bool
		outcome string
	}{
		{"T0 for anyone", nil, Pool{}, Entry{}, Requester{Kind: "none"}, true, "t0"},
		{"over the ceiling", member, Pool{Identity: "claude-session", Ceiling: "T0"}, t1, alice, false, "pool_ceiling"},
		{"Cursor pool, T1", member, Pool{Identity: "none", Ceiling: "T1"}, t1, alice, false, "no_identity"},
		{"agent session", member, claude, t1, Requester{Kind: "agent", Subject: "agent:x"}, false, "no_person"},
		{"member", member, claude, t1, alice, true, "entitled"},
		{"Cursor person pool member", member, Pool{Identity: "cursor-session", Ceiling: "T1"}, t1, alice, true, "entitled"},
		{"Cursor service account run", member, Pool{Identity: "cursor-session", Ceiling: "T1"}, t1, Requester{Kind: "agent", Subject: "service_account:9"}, false, "no_person"},
		{"Cursor run without a person", member, Pool{Identity: "cursor-session", Ceiling: "T1"}, t1, Requester{Kind: "none"}, false, "no_person"},
		{"non-member", &fakeSource{person: Person{ObjectID: "oid", Enabled: true}}, claude, t1, alice, false, "not_entitled"},
		{"disabled", &fakeSource{person: Person{ObjectID: "oid", MemberOf: []string{g1}}}, claude, t1, alice, false, "account_disabled"},
		{"lookup error", &fakeSource{err: errors.New("down")}, claude, t1, alice, false, "entitlement_unavailable"},
		{"workload entitled", nil, Pool{Identity: "workload", Ceiling: "T1", Entitlements: []string{g1}}, t1, Requester{Kind: "workload"}, true, "workload_entitled"},
		{"workload missing group", nil, Pool{Identity: "workload", Ceiling: "T1"}, t1, Requester{Kind: "workload"}, false, "workload_not_entitled"},
		{"workload T2", nil, Pool{Identity: "workload", Ceiling: "T2", Entitlements: []string{g1}}, Entry{Tier: "T2", Requires: []string{g1}}, Requester{Kind: "workload"}, false, "workload_not_entitled"},
	}
	for _, c := range cases {
		cache := &Cache{Source: c.source}
		d := Decide(context.Background(), cache, c.pool, c.entry, c.who)
		if d.Allowed != c.allowed || d.Outcome != c.outcome {
			t.Errorf("%s: got %v %q", c.name, d.Allowed, d.Outcome)
		}
	}
}

func TestCacheBoundsOffboardingAndNeverCachesErrors(t *testing.T) {
	now := time.Now()
	source := &fakeSource{person: Person{ObjectID: "oid", Enabled: true, MemberOf: []string{g1}}}
	cache := &Cache{Source: source, TTL: time.Minute, Now: func() time.Time { return now }}
	claude := Pool{Identity: "claude-session", Ceiling: "T1"}
	t1 := Entry{Tier: "T1", Requires: []string{g1}}
	alice := Requester{Kind: "person", Subject: "sso|alice"}
	if !Decide(context.Background(), cache, claude, t1, alice).Allowed {
		t.Fatal("member refused")
	}
	source.person.MemberOf = nil // removed from the group
	now = now.Add(30 * time.Second)
	if d := Decide(context.Background(), cache, claude, t1, alice); !d.Allowed || d.CacheAge != 30*time.Second {
		t.Fatalf("within the TTL the cached answer stands: %+v", d)
	}
	now = now.Add(31 * time.Second)
	if Decide(context.Background(), cache, claude, t1, alice).Allowed {
		t.Fatal("offboarding did not take effect after the TTL")
	}
	source.err = errors.New("down")
	now = now.Add(2 * time.Minute)
	calls := source.calls
	_ = Decide(context.Background(), cache, claude, t1, alice)
	_ = Decide(context.Background(), cache, claude, t1, alice)
	if source.calls != calls+2 {
		t.Fatal("a lookup error was cached")
	}
	if (&Cache{Source: source, TTL: time.Hour}).TTL > 0 {
		capped := &Cache{Source: &fakeSource{person: Person{Enabled: true}}, TTL: time.Hour, Now: func() time.Time { return now }}
		_, _, _ = capped.Lookup(context.Background(), "s", nil)
		now = now.Add(MaxCacheTTL + time.Second)
		if _, age, _ := capped.Lookup(context.Background(), "s", nil); age != 0 {
			t.Fatal("cache TTL above five minutes was honored")
		}
	}
}

func TestFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dir.json")
	_ = os.WriteFile(path, []byte(`{"subjects":{"sso|alice":{"objectID":"oid","enabled":true,"groups":["`+g1+`"]}}}`), 0o600)
	p, err := FileSource{Path: path}.Lookup(context.Background(), "sso|alice", []string{g1, "other"})
	if err != nil || !p.Enabled || len(p.MemberOf) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := (FileSource{Path: path}).Lookup(context.Background(), "sso|bob", nil); err == nil {
		t.Fatal("unknown subject resolved")
	}
}

func TestGraphSource(t *testing.T) {
	user := "22222222-2222-2222-2222-222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer app-token" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/users/alice@example.test":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": user, "accountEnabled": true})
		case r.Method == http.MethodPost && r.URL.Path == "/users/"+user+"/checkMemberGroups":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []string{g1}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	g := GraphSource{Endpoint: srv.URL, Client: srv.Client(), Token: func(context.Context) (string, error) { return "app-token", nil }}
	p, err := g.Lookup(context.Background(), "alice@example.test", []string{g1})
	if err != nil || p.ObjectID != user || len(p.MemberOf) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := g.Lookup(context.Background(), "bob@example.test", []string{g1}); err == nil {
		t.Fatal("missing user resolved")
	}
	if _, err := g.Lookup(context.Background(), "alice@example.test", []string{"not-an-id"}); err == nil {
		t.Fatal("non-ID group accepted")
	}
}

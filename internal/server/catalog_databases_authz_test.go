package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

const (
	t1Group = "11111111-1111-1111-1111-111111111111"
	t2Group = "22222222-2222-2222-2222-222222222222"
)

type fakeRunner map[string]runnerid.Session

func (f fakeRunner) Verify(_ context.Context, token string) (runnerid.Session, error) {
	if s, ok := f[token]; ok {
		return s, nil
	}
	return runnerid.Session{}, runnerid.ErrInvalid
}

type directory map[string][]string

func (d directory) Lookup(_ context.Context, subject string, groups []string) (entitlement.Person, error) {
	have, ok := d[subject]
	if !ok {
		return entitlement.Person{}, errors.New("unknown")
	}
	var member []string
	for _, g := range groups {
		for _, h := range have {
			if g == h {
				member = append(member, g)
			}
		}
	}
	return entitlement.Person{ObjectID: "oid-" + subject, Enabled: true, MemberOf: member}, nil
}

func TestCatalogDatabaseResolverAppliesTheAuthorizationModel(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T2"}],
	 "entries":[
	  {"name":"open","kind":"postgres","host":"db.example","pools":["cursor","claude"],"postgres":{"database":"open","mount":"database","role":"staging.us.crunchy.open-readonly"}},
	  {"name":"t1db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T1","requires":["` + t1Group + `"],"postgres":{"database":"t1db","mount":"database","role":"staging.us.crunchy.t1-readonly"}},
	  {"name":"t2db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T2","requires":["` + t2Group + `"],"postgres":{"database":"t2db","mount":"database","role":"staging.us.crunchy.t2-readonly"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{
		"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"carol": {Kind: runnerid.KindPerson, Subject: "sso|carol", Pools: []string{"ccpool_abc"}, TokenSHA256: "cc"},
		"bob":   {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}},
		"slack": {Kind: runnerid.KindAgent, Subject: "agent:1", Pools: []string{"ccpool_abc"}},
		"other": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_zzz"}},
	}
	cache := &entitlement.Cache{Source: directory{"sso|alice": {t1Group}, "sso|carol": {t1Group, t2Group}, "sso|bob": {}}}
	r := NewCatalogDatabaseResolver(httpcatalog.NewSource(catalog, 1), runner, cache, &authorizetest.MemBinder{})
	cases := []struct{ name, pool, token, database, want string }{
		{"Cursor pool, T0", "cursor", "", "open", ""},
		{"Claude pool, T0, no session", "claude", "", "open", ""},
		{"T1 member", "claude", "alice", "t1db", ""},
		{"T1 non-member", "claude", "bob", "t1db", "not_entitled"},
		{"T1 without a session", "claude", "", "t1db", "no_person"},
		{"T1 for an agent session", "claude", "slack", "t1db", "no_person"},
		{"T1 forged token", "claude", "forged", "t1db", "session_token"},
		{"forged token even for T0", "claude", "forged", "open", "session_token"},
		{"T1 token for another runner pool", "claude", "other", "t1db", "session_pool"},
		{"T2 member", "claude", "carol", "t2db", ""},
		{"T2 refused to a T1-only person", "claude", "alice", "t2db", "not_entitled"},
		{"a session on a pool that takes none", "cursor", "alice", "open", "session_unexpected"},
	}
	for _, c := range cases {
		ctx := pgproxy.WithSession(context.Background(), c.token)
		_, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{ActorID: "a", Pool: c.pool, WorkloadID: "pod-a"}, c.database)
		var refused *pgproxy.RefusedError
		got := ""
		if errors.As(err, &refused) {
			got = refused.Outcome
		} else if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	// The catalog itself never grants a T1 database to the Cursor pool.
	if _, err := r.ResolveDatabase(pgproxy.WithSession(context.Background(), "alice"), pgproxy.AgentScope{ActorID: "a", Pool: "cursor", WorkloadID: "pod-a"}, "t1db"); err == nil {
		t.Fatal("Cursor pool resolved a T1 database")
	}
}

type countingDirectory struct {
	directory
	asks int
}

func (c *countingDirectory) Lookup(ctx context.Context, subject string, groups []string) (entitlement.Person, error) {
	c.asks++
	return c.directory.Lookup(ctx, subject, groups)
}

// The broker's recheck mark reaches the decision: a T2 admission asks the
// directory every time, a T2 recheck may use the cache, and a refused recheck
// purges the person.
func TestCatalogDatabaseResolverFreshT2AdmissionsAndPurge(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T2"}],
	 "entries":[
	  {"name":"t1db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T1","requires":["` + t1Group + `"],"postgres":{"database":"t1db","mount":"database","role":"staging.us.crunchy.t1-readonly"}},
	  {"name":"t2db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T2","requires":["` + t2Group + `"],"postgres":{"database":"t2db","mount":"database","role":"staging.us.crunchy.t2-readonly"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	dir := &countingDirectory{directory: directory{"sso|carol": {t1Group, t2Group}}}
	r := NewCatalogDatabaseResolver(httpcatalog.NewSource(catalog, 1),
		fakeRunner{"carol": {Kind: runnerid.KindPerson, Subject: "sso|carol", Pools: []string{"ccpool_abc"}}},
		&entitlement.Cache{Source: dir, TTL: time.Minute}, &authorizetest.MemBinder{})
	scope := pgproxy.AgentScope{ActorID: "a", Pool: "claude", WorkloadID: "pod-a"}
	admit := pgproxy.WithSession(context.Background(), "carol")
	recheck := pgproxy.WithRecheck(admit)
	resolve := func(ctx context.Context, db string) error { _, err := r.ResolveDatabase(ctx, scope, db); return err }
	if resolve(admit, "t1db") != nil || resolve(admit, "t2db") != nil || resolve(admit, "t2db") != nil {
		t.Fatal("carol refused")
	}
	if dir.asks != 3 {
		t.Fatalf("asks %d, want 3 (one T1, two fresh T2)", dir.asks)
	}
	if resolve(recheck, "t2db") != nil || dir.asks != 3 {
		t.Fatalf("T2 recheck did not use the cache (asks %d)", dir.asks)
	}
	dir.directory["sso|carol"] = nil
	if resolve(admit, "t2db") == nil {
		t.Fatal("T2 admission after removal rode the cache")
	}
	if resolve(recheck, "t2db") == nil {
		t.Fatal("recheck allowed a removed person")
	}
	if resolve(admit, "t1db") == nil {
		t.Fatal("T1 after a refused recheck rode the cache")
	}
}

// An agent-sandbox pool in person mode authorizes the person its shared proxy
// attested, on the database path as on HTTP; a pool-mode pool refuses one.
func TestCatalogDatabaseResolverAuthorizesTheAttestedPerson(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	domain := `"trustDomain":{"issuer":"https://container.googleapis.com/v1/projects/s/locations/l/clusters/sandbox","keys":"remote","audience":"gatehouse"}`
	harness := func(name, requester, mode string) string {
		return `{"name":"` + name + `",` + domain + `,"identity":{"kind":"proxy-attested","ownerKind":"Sandbox","namespaces":["` + name + `"],"imageDigests":["sha256:1111111111111111111111111111111111111111111111111111111111111111"]` + requester + `},` +
			`"path":{"kind":"shared-proxy","crossCluster":true},"authorization":{"mode":"` + mode + `","poolName":"` + name + `"},"client":{"proxyEnv":"HTTPS_PROXY","caFileEnv":"SSL_CERT_FILE"}}`
	}
	catalog, err := httpcatalog.Parse([]byte(`{"harnesses":[` + harness("developers", `,"requester":{"kind":"pod-annotation"}`, "person") + `,` + harness("shared", "", "pool") + `],
	 "pools":[{"name":"developers","namespace":"developers","serviceAccount":"sandbox","identity":"attested-person","ceiling":"T2"},
	  {"name":"shared","namespace":"shared","serviceAccount":"sandbox"}],
	 "entries":[
	  {"name":"open","kind":"postgres","host":"db.example","pools":["developers","shared"],"postgres":{"database":"open","mount":"database","role":"staging.us.crunchy.open-readonly"}},
	  {"name":"t1db","kind":"postgres","host":"db.example","pools":["developers"],"tier":"T1","requires":["` + t1Group + `"],"postgres":{"database":"t1db","mount":"database","role":"staging.us.crunchy.t1-readonly"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cache := &entitlement.Cache{Source: directory{"alice.smith@trmlabs.com": {t1Group}, "bob@trmlabs.com": {}}}
	r := NewCatalogDatabaseResolver(httpcatalog.NewSource(catalog, 1), runnerid.Verifiers{SandboxDomains: []string{"trmlabs.com"}}, cache, &authorizetest.MemBinder{})
	for _, c := range []struct{ name, pool, requester, database, want string }{
		{"T1 member", "developers", "alice.smith@trmlabs.com", "t1db", ""},
		{"T1 non-member", "developers", "bob@trmlabs.com", "t1db", "not_entitled"},
		{"outside the person domains", "developers", "alice@example.com", "t1db", "no_person"},
		{"no requester attested", "developers", "", "open", "requester_missing"},
		{"pool mode, no requester", "shared", "", "open", ""},
		{"pool mode with a requester", "shared", "alice.smith@trmlabs.com", "open", "requester_unexpected"},
	} {
		_, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "a", Pool: c.pool, WorkloadID: "pod-a", AttestedRequester: c.requester}, c.database)
		var refused *pgproxy.RefusedError
		got := ""
		if errors.As(err, &refused) {
			got = refused.Outcome
		} else if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

package server

import (
	"context"
	"errors"
	"testing"

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
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T2"}],
	 "entries":[
	  {"name":"open","kind":"postgres","host":"db.example","pools":["cursor","claude"],"postgres":{"database":"open","mount":"database","role":"open-ro"}},
	  {"name":"t1db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T1","requires":["` + t1Group + `"],"postgres":{"database":"t1db","mount":"database","role":"t1-ro"}},
	  {"name":"t2db","kind":"postgres","host":"db.example","pools":["claude"],"tier":"T2","requires":["` + t2Group + `"],"postgres":{"database":"t2db","mount":"database","role":"t2-ro"}}]}`))
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
	r := NewCatalogDatabaseResolver(httpcatalog.NewSource(catalog, 1), runner, cache)
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
		_, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{ActorID: "a", Pool: c.pool}, c.database)
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
	if _, err := r.ResolveDatabase(pgproxy.WithSession(context.Background(), "alice"), pgproxy.AgentScope{ActorID: "a", Pool: "cursor"}, "t1db"); err == nil {
		t.Fatal("Cursor pool resolved a T1 database")
	}
}

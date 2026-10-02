package mitm

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

const authzGroup = "11111111-1111-1111-1111-111111111111"

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

func authzProxy(t *testing.T) (*Proxy, *httpcatalog.Entry, *httpcatalog.Entry) {
	t.Helper()
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	 "entries":[
	  {"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"m","path":"p","field":"f"},"pools":["cursor","claude"]},
	  {"name":"gated","host":"api.vendor.example","pathPrefixes":["/gated/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"m","path":"p","field":"f"},"pools":["claude"],"tier":"T1","requires":["` + authzGroup + `"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{
		"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"bob":   {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"},
		"slack": {Kind: runnerid.KindAgent, Subject: "agent:1", Pools: []string{"ccpool_abc"}},
		"other": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_zzz"}},
	}
	p := &Proxy{adapter: &HeaderAdapter{Catalog: catalog, Runner: runner, Sessions: &authorizetest.MemBinder{},
		Entitlements: &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}, "sso|bob": {}}}}}
	open, _ := catalog.Match("api.vendor.example", 443, "GET", "/open/x", "claude")
	gated, _ := catalog.Match("api.vendor.example", 443, "GET", "/gated/x", "claude")
	return p, open, gated
}

func TestAuthorizeModel(t *testing.T) {
	p, open, gated := authzProxy(t)
	cases := []struct {
		name, pool, token string
		entry             *httpcatalog.Entry
		want              string
	}{
		{"Cursor pool, T0", "cursor", "", open, ""},
		{"Cursor pool, T1 (defense in depth; the catalog never grants it)", "cursor", "", gated, "pool_ceiling"},
		{"member", "claude", "alice", gated, ""},
		{"non-member", "claude", "bob", gated, "not_entitled"},
		{"no session token", "claude", "", gated, "no_person"},
		{"forged token", "claude", "forged", gated, "session_token"},
		{"forged token even for T0", "claude", "forged", open, "session_token"},
		{"agent session, T1", "claude", "slack", gated, "no_person"},
		{"agent session, T0", "claude", "slack", open, ""},
		{"token for another runner pool", "claude", "other", gated, "session_pool"},
		{"a session on a pool that takes none", "cursor", "alice", open, "session_unexpected"},
	}
	for _, c := range cases {
		event := auditchain.Event{}
		ctx := withSessionToken(context.Background(), c.token)
		got := p.authorize(ctx, &brokercore.ProxyScope{Pool: c.pool, AgentID: "a", WorkloadID: "pod-a"}, c.entry, &event)
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
		if c.token == "alice" && c.pool == "claude" && (event.Requester != "sso|alice" || event.RequesterOID != "oid-sso|alice" || event.TokenSHA256 != "aa" || event.Decision != "entitled") {
			t.Errorf("%s: audit fields %+v", c.name, event)
		}
	}
}

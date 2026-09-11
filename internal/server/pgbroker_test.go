package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDatabaseServices_Inline(t *testing.T) {
	env := map[string]string{
		"AGENT_VAULT_DB_SERVICES": `{"default":[{"name":"analytics","upstream":"127.0.0.1:5433","database":"appdb","mount":"database","role":"readonly"}]}`,
	}
	got, err := LoadDatabaseServices(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadDatabaseServices: %v", err)
	}
	svcs := got["default"]
	if len(svcs) != 1 {
		t.Fatalf("want 1 service, got %d", len(svcs))
	}
	want := pgproxy.DatabaseService{Name: "analytics", Addr: "127.0.0.1:5433", Database: "appdb", Mount: "database", Role: "readonly"}
	if svcs[0] != want {
		t.Fatalf("service = %+v, want %+v", svcs[0], want)
	}
}

func TestLoadDatabaseServices_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svcs.json")
	if err := os.WriteFile(path, []byte(`{"team-a":[{"name":"db","upstream":"db.internal:5432","mount":"database","role":"ro"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDatabaseServices(getenvFrom(map[string]string{"AGENT_VAULT_DB_SERVICES_FILE": path}))
	if err != nil {
		t.Fatalf("LoadDatabaseServices: %v", err)
	}
	if len(got["team-a"]) != 1 || got["team-a"][0].Addr != "db.internal:5432" {
		t.Fatalf("unexpected services: %+v", got)
	}
}

func TestLoadDatabaseServices_Empty(t *testing.T) {
	got, err := LoadDatabaseServices(getenvFrom(nil))
	if err != nil {
		t.Fatalf("LoadDatabaseServices: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty map, got %+v", got)
	}
}

func TestLoadDatabaseServices_Errors(t *testing.T) {
	cases := map[string]string{
		"bad json":       `{not-json`,
		"missing name":   `{"v":[{"upstream":"h:1","mount":"database","role":"ro"}]}`,
		"missing mount":  `{"v":[{"name":"n","upstream":"h:1","role":"ro"}]}`,
		"missing role":   `{"v":[{"name":"n","upstream":"h:1","mount":"database"}]}`,
		"bad upstream":   `{"v":[{"name":"n","upstream":"no-port","mount":"database","role":"ro"}]}`,
		"missing upstre": `{"v":[{"name":"n","mount":"database","role":"ro"}]}`,
		"bad sslmode":    `{"v":[{"name":"n","upstream":"h:1","mount":"database","role":"ro","sslmode":"verify_full"}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadDatabaseServices(getenvFrom(map[string]string{"AGENT_VAULT_DB_SERVICES": raw})); err == nil {
				t.Fatalf("expected an error for %q", name)
			}
		})
	}
}

func TestLoadDatabaseServices_InlineWinsOverFile(t *testing.T) {
	// When both are set, the inline var takes precedence over the file.
	env := map[string]string{
		"AGENT_VAULT_DB_SERVICES":      `{"v":[{"name":"inline","upstream":"h:1","mount":"database","role":"ro"}]}`,
		"AGENT_VAULT_DB_SERVICES_FILE": "/nonexistent/should-not-be-read.json",
	}
	got, err := LoadDatabaseServices(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadDatabaseServices: %v", err)
	}
	if len(got["v"]) != 1 || got["v"][0].Name != "inline" {
		t.Fatalf("inline var should win, got %+v", got)
	}
}

func TestLoadDatabaseServices_FileNotFound(t *testing.T) {
	_, err := LoadDatabaseServices(getenvFrom(map[string]string{"AGENT_VAULT_DB_SERVICES_FILE": "/nonexistent/db-services.json"}))
	if err == nil {
		t.Fatal("expected an error when the services file is missing")
	}
}

func TestLoadDatabaseServices_SSLMode(t *testing.T) {
	env := map[string]string{
		"AGENT_VAULT_DB_SERVICES": `{"v":[{"name":"s","upstream":"h:1","mount":"database","role":"ro","sslmode":"verify-full"}]}`,
	}
	got, err := LoadDatabaseServices(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadDatabaseServices: %v", err)
	}
	if got["v"][0].SSLMode != "verify-full" {
		t.Fatalf("sslmode not carried through: %+v", got["v"][0])
	}
}

func TestStaticDatabaseResolver(t *testing.T) {
	byVault := map[string][]pgproxy.DatabaseService{
		"solo":  {{Name: "only", Addr: "h:5432", Mount: "database", Role: "ro"}},
		"multi": {{Name: "reads", Database: "analytics", Addr: "h:1", Mount: "database", Role: "ro"}, {Name: "writes", Database: "ledger", Addr: "h:2", Mount: "database", Role: "rw"}},
	}
	r := NewStaticDatabaseResolver(byVault)
	ctx := context.Background()

	// Even a sole service requires an explicit match.
	svc, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultName: "solo"}, "only")
	if err != nil || svc.Name != "only" {
		t.Fatalf("solo resolve = %+v, %v", svc, err)
	}

	// Multi: match by service name.
	svc, err = r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultName: "multi"}, "writes")
	if err != nil || svc.Name != "writes" {
		t.Fatalf("name resolve = %+v, %v", svc, err)
	}
	// Multi: match by upstream database name.
	svc, err = r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultName: "multi"}, "analytics")
	if err != nil || svc.Name != "reads" {
		t.Fatalf("database resolve = %+v, %v", svc, err)
	}
	// Multi: no match.
	if _, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultName: "multi"}, "nope"); err == nil {
		t.Fatal("expected no-match error")
	}
	// Unknown vault.
	if _, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultName: "ghost"}, "x"); err == nil {
		t.Fatal("expected error for a vault with no services")
	}
}

func TestStoreDatabaseResolver(t *testing.T) {
	ms := newMockStore()
	ctx := context.Background()
	// Two services in vault "v-multi" (id "vid-multi"), one in a solo vault.
	for _, svc := range []store.DatabaseService{
		{VaultID: "vid-multi", Name: "reads", Upstream: "h:1", Database: "analytics", Mount: "database", Role: "ro", SSLMode: "require", MaxConns: 5},
		{VaultID: "vid-multi", Name: "writes", Upstream: "h:2", Database: "ledger", Mount: "database", Role: "rw"},
		{VaultID: "vid-solo", Name: "only", Upstream: "h:9", Mount: "database", Role: "ro"},
	} {
		if _, err := ms.UpsertDatabaseService(ctx, svc); err != nil {
			t.Fatalf("seed %s: %v", svc.Name, err)
		}
	}
	r := NewStoreDatabaseResolver(ms)

	// Keys by scope.VaultID (not name); maps Upstream->Addr and carries fields.
	svc, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "vid-multi", VaultName: "v-multi"}, "reads")
	if err != nil {
		t.Fatalf("resolve reads: %v", err)
	}
	want := pgproxy.DatabaseService{Name: "reads", Addr: "h:1", Database: "analytics", Mount: "database", Role: "ro", SSLMode: "require", MaxConns: 5}
	if *svc != want {
		t.Fatalf("mapped service = %+v, want %+v", *svc, want)
	}

	// Match by upstream database name.
	if svc, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "vid-multi"}, "ledger"); err != nil || svc.Name != "writes" {
		t.Fatalf("database-name resolve = %+v, %v", svc, err)
	}
	// Sole service still matches its name.
	if svc, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "vid-solo"}, "only"); err != nil || svc.Name != "only" {
		t.Fatalf("solo resolve = %+v, %v", svc, err)
	}
	// No match in a multi-service vault.
	if _, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "vid-multi"}, "nope"); err == nil {
		t.Fatal("expected no-match error")
	}
	// A vault with no services.
	if _, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "vid-empty", VaultName: "empty"}, "x"); err == nil {
		t.Fatal("expected error for a vault with no services")
	}
}

func TestSeedDatabaseServices(t *testing.T) {
	ms := newMockStore() // seeds vault "default" (id root-ns-id)
	srv := newTestServer(withStore(ms))
	ctx := context.Background()

	// A service already present (modelling a runtime edit) must not be clobbered.
	if _, err := ms.UpsertDatabaseService(ctx, store.DatabaseService{
		VaultID: "root-ns-id", Name: "edited", Upstream: "runtime:5432", Mount: "database", Role: "rw",
	}); err != nil {
		t.Fatalf("pre-seed edit: %v", err)
	}

	seeded, err := srv.SeedDatabaseServices(ctx, map[string][]pgproxy.DatabaseService{
		"default": {
			{Name: "edited", Addr: "config:5432", Mount: "database", Role: "ro"}, // same name -> skipped
			{Name: "fresh", Addr: "new:5432", Mount: "database", Role: "ro"},     // new -> inserted
		},
		"ghost": {{Name: "x", Addr: "h:1", Mount: "database", Role: "ro"}}, // unknown vault -> skipped
	})
	if err != nil {
		t.Fatalf("SeedDatabaseServices: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("expected exactly 1 seeded (fresh), got %d", seeded)
	}

	// The runtime edit survived (insert-if-absent did not clobber it).
	if got, _ := ms.GetDatabaseService(ctx, "root-ns-id", "edited"); got == nil || got.Upstream != "runtime:5432" || got.Role != "rw" {
		t.Fatalf("runtime edit was clobbered: %+v", got)
	}
	// The fresh service was inserted.
	if got, _ := ms.GetDatabaseService(ctx, "root-ns-id", "fresh"); got == nil || got.Upstream != "new:5432" {
		t.Fatalf("fresh service not seeded: %+v", got)
	}
	// The unknown vault was skipped, not created.
	if list, _ := ms.ListDatabaseServices(ctx, "ghost"); len(list) != 0 {
		t.Fatalf("unknown vault should be skipped, got %+v", list)
	}
}

type fakeSessionResolver struct {
	scope *brokercore.ProxyScope
	err   error
}

func (f fakeSessionResolver) ResolveForProxy(_ context.Context, _, _ string) (*brokercore.ProxyScope, error) {
	return f.scope, f.err
}

func TestAgentAuthAdapter(t *testing.T) {
	adapter := NewAgentAuthAdapter(fakeSessionResolver{scope: &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", AgentID: "agent-9"}})
	scope, err := adapter.Authenticate(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if scope.VaultID != "v1" || scope.VaultName != "default" || scope.ActorID != "agent-9" {
		t.Fatalf("scope = %+v", scope)
	}

	failing := NewAgentAuthAdapter(fakeSessionResolver{err: fmt.Errorf("invalid session")})
	if _, err := failing.Authenticate(context.Background(), "bad", ""); err == nil {
		t.Fatal("expected error passthrough")
	}
}

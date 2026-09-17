package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestAdversarial_NonOwnerCannotBindSharedVaultIdentity(t *testing.T) {
	srv, ms, _, member := setupDatabaseAPITest(t)
	session, err := ms.GetSession(context.Background(), member)
	if err != nil {
		t.Fatal(err)
	}
	if err := ms.GrantVaultRole(context.Background(), session.UserID, "user", "root-ns-id", "admin"); err != nil {
		t.Fatal(err)
	}
	response := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", member, `{"name":"privileged","upstream":"db.internal:5432","database":"appdb","mount":"database","role":"other-team-admin"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-owner vault admin can bind arbitrary shared Vault role: HTTP %d", response.Code)
	}
}

func TestAdversarial_RemovingTwoToOneRejectsRemovedName(t *testing.T) {
	services := []pgproxy.DatabaseService{{Name: "analytics", Database: "appdb"}, {Name: "orders", Database: "ordersdb"}}
	if _, err := selectDatabaseService(services, "v", "orders"); err != nil {
		t.Fatal(err)
	}
	got, err := selectDatabaseService(services[:1], "v", "orders")
	if err == nil {
		t.Fatalf("removed name orders silently resolves to %s/%s", got.Name, got.Database)
	}
}

func TestAdversarial_ExactNameWinsOverDatabaseAlias(t *testing.T) {
	services := []pgproxy.DatabaseService{{Name: "a-readonly", Database: "analytics", Role: "readonly"}, {Name: "analytics", Database: "appdb", Role: "writer"}}
	got, err := selectDatabaseService(services, "v", "analytics")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "analytics" {
		t.Fatalf("exact service name analytics resolves to %s (role %s)", got.Name, got.Role)
	}
}

func TestDatabaseResolverRejectsAmbiguousAlias(t *testing.T) {
	services := []pgproxy.DatabaseService{{Name: "read", Database: "shared"}, {Name: "write", Database: "shared"}}
	if _, err := selectDatabaseService(services, "v", "shared"); err == nil {
		t.Fatal("ambiguous alias accepted")
	}
}

func TestDatabaseResolverSharedBudgetFollowsLiveChanges(t *testing.T) {
	ms := newMockStore()
	ctx := context.Background()
	ms.UpsertDatabaseService(ctx, store.DatabaseService{VaultID: "one", Name: "read", Upstream: "db:5432", MaxConns: 10})
	ms.UpsertDatabaseService(ctx, store.DatabaseService{VaultID: "two", Name: "write", Upstream: "db:5432", MaxConns: 2})
	r := NewStoreDatabaseResolver(ms)
	svc, err := r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "one"}, "read")
	if err != nil || svc.MaxConns != 2 {
		t.Fatalf("shared limit: %v, %v", svc, err)
	}
	ms.UpsertDatabaseService(ctx, store.DatabaseService{VaultID: "two", Name: "write", Upstream: "db:5432", MaxConns: 1})
	svc, err = r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "one"}, "read")
	if err != nil || svc.MaxConns != 1 {
		t.Fatalf("updated shared limit: %v, %v", svc, err)
	}
	ms.DeleteDatabaseService(ctx, "two", "write")
	svc, err = r.ResolveDatabase(ctx, pgproxy.AgentScope{VaultID: "one"}, "read")
	if err != nil || svc.MaxConns != 10 {
		t.Fatalf("removed shared limit: %v, %v", svc, err)
	}
}

func TestDatabaseConfigValidation(t *testing.T) {
	valid := DatabaseServiceConfig{Name: "db", Upstream: "localhost:5432", Mount: "database", Role: "readonly"}
	for name, edit := range map[string]func(*DatabaseServiceConfig){
		"empty host":     func(c *DatabaseServiceConfig) { c.Upstream = ":5432" },
		"bad port":       func(c *DatabaseServiceConfig) { c.Upstream = "host:99999" },
		"service path":   func(c *DatabaseServiceConfig) { c.Name = "db/other" },
		"role traversal": func(c *DatabaseServiceConfig) { c.Role = "../config/admin" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			edit(&c)
			if err := c.Validate("vault"); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestServerFailsFastWhenPostgresPortIsOccupied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := newTestServer()
	srv.AttachPostgresBroker(pgproxy.New(ln.Addr().String(), pgproxy.Options{}))
	if err := srv.Start(); err == nil || !strings.Contains(err.Error(), "listen postgres broker") {
		t.Fatalf("expected synchronous postgres bind error, got %v", err)
	}
}

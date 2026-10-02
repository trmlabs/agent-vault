package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

const databaseCatalog = `{"pools":[{"name":"cursor","namespace":"agents","serviceAccount":"cursor-worker"},{"name":"ci","namespace":"ci","serviceAccount":"runner"}],
"entries":[
 {"name":"b2bcore","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"core","mount":"database","role":"staging.us.crunchy.core-readonly","maxConns":20}},
 {"name":"auditlog","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor","ci"],
  "postgres":{"database":"auditlog","mount":"database","role":"staging.us.crunchy.auditlog-readonly","sslmode":"verify-full","maxConns":5}}]}`

func TestCatalogDatabaseResolverFollowsTheLiveCatalog(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	first, err := httpcatalog.Parse([]byte(databaseCatalog))
	if err != nil {
		t.Fatal(err)
	}
	source := httpcatalog.NewSource(first, 1)
	r := NewCatalogDatabaseResolver(source)
	svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "b2bcore")
	if err != nil || svc.Addr != "p.abc.db.postgresbridge.com:5432" || svc.Database != "core" || svc.SSLMode != "verify-full" || svc.MaxConns != 5 {
		t.Fatalf("resolved %+v %v", svc, err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-2", Pool: "ci"}, "b2bcore"); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("ungranted pool: %v", err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1"}, "b2bcore"); err == nil {
		t.Fatal("a scope without a catalog pool resolved a database")
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "detect"); err == nil {
		t.Fatal("unknown database resolved")
	}
	// A reload that adds a database makes it reachable with no restart.
	added := strings.Replace(databaseCatalog, `]}`, `,{"name":"detect","kind":"postgres","host":"p.def.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"detect","mount":"database","role":"staging.us.crunchy.detect-readonly"}}]}`, 1)
	if strings.Count(added, "detect") < 2 {
		t.Fatal("test catalog not extended")
	}
	if _, err := httpcatalog.Parse([]byte(added)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 10*time.Millisecond, func(context.Context) ([]byte, int, error) { return []byte(added), 2, nil }, func(int, error) {})
	for deadline := time.Now().Add(2 * time.Second); source.Version() != 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("catalog not reloaded")
		}
	}
	if svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "detect"); err != nil || svc.Database != "detect" {
		t.Fatalf("reloaded database: %+v %v", svc, err)
	}
}

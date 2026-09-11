//go:build realpg

package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The fixture allows the broker route and rejects the agent route with pg_hba.
// See examples/postgres-broker/README.md. This test explicitly proves that the
// network policy, not SQL filtering, closes the self-password-change escape.
func TestRealPostgres_NetworkIsolationBlocksChosenPassword(t *testing.T) {
	allowed, denied := os.Getenv("AV_TEST_PG_UPSTREAM"), os.Getenv("AV_TEST_PG_DENIED_UPSTREAM")
	if allowed == "" || denied == "" {
		t.Skip("requires isolated PostgreSQL broker/agent routes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, os.Getenv("AV_TEST_PG_ADMIN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	role := fmt.Sprintf("av_isolation_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	const initial = "synthetic-initial-password"
	const chosen = "synthetic-agent-chosen-password"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN PASSWORD '"+initial+"' IN ROLE pg_read_all_data"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP ROLE "+roleSQL) }()
	lease := &Lease{ID: "test-isolation", Username: role, Password: initial, ExpiresAt: time.Now().Add(time.Minute)}
	_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "test", ActorID: "agent"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "app", Addr: allowed, Database: "appdb"}}, Leases: &fakeMinter{lease: lease}})
	agent, err := pgx.Connect(ctx, "postgres://agent:synthetic-token@"+addr+"/app?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close(context.Background())
	if _, err := agent.Exec(ctx, "ALTER ROLE CURRENT_USER PASSWORD '"+chosen+"'"); err != nil {
		t.Fatal(err)
	}
	connect := func(addr string) (*pgx.Conn, error) {
		cfg, err := pgx.ParseConfig("postgres://" + addr + "/appdb?sslmode=disable")
		if err != nil {
			return nil, err
		}
		cfg.User, cfg.Password = role, chosen
		return pgx.ConnectConfig(ctx, cfg)
	}
	// Control: the chosen password works from the trusted broker route.
	control, err := connect(allowed)
	if err != nil {
		t.Fatalf("control connection: %v", err)
	}
	_ = control.Close(ctx)
	escaped, err := connect(denied)
	if err == nil {
		_ = escaped.Close(ctx)
		t.Fatal("agent route bypassed isolation")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "28000" {
		t.Fatalf("want HBA policy rejection, got %v", err)
	}
	var one int
	if err := agent.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatal(err)
	}
}

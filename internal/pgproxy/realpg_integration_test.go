//go:build realpg

// Package pgproxy real-PostgreSQL integration test. It is guarded by the
// `realpg` build tag and skips unless pointed at a running PostgreSQL via
// environment variables, so the default `go test ./...` (and CI without a
// database) is unaffected. Run with:
//
//	AV_TEST_PG_UPSTREAM=127.0.0.1:5433 \
//	AV_TEST_PG_ADMIN='postgres://vault_admin:vault-bootstrap-pw@127.0.0.1:5433/appdb?sslmode=disable' \
//	AV_TEST_PG_DB=appdb \
//	go test -tags realpg ./internal/pgproxy/ -run RealPostgres -v
//
// It stands in for Vault with a fakeMinter that returns a real, pre-created
// database role, proving the wire proxy authenticates to a real PostgreSQL over
// SCRAM-SHA-256 and relays a real libpq (pgx) client session.
package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRealPostgres_EndToEnd(t *testing.T) {
	upstream := os.Getenv("AV_TEST_PG_UPSTREAM")
	adminDSN := os.Getenv("AV_TEST_PG_ADMIN")
	database := os.Getenv("AV_TEST_PG_DB")
	if upstream == "" || adminDSN == "" || database == "" {
		t.Skip("set AV_TEST_PG_UPSTREAM, AV_TEST_PG_ADMIN, AV_TEST_PG_DB to run the real-PostgreSQL integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	const roleName = "av_it_readonly"
	const rolePassword = "it-scram-pw"
	// Recreate the role so the test is idempotent, then grant read access the way
	// a Vault database role's creation statements would.
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+roleName)
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' IN ROLE pg_read_all_data`, roleName, rolePassword)); err != nil {
		t.Fatalf("create role: %v", err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+roleName) }()

	lease := &Lease{ID: "it-lease-1", Username: roleName, Password: rolePassword, ExpiresAt: time.Now().Add(time.Hour), Renewable: false}
	minter := &fakeMinter{lease: lease}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	broker := New(ln.Addr().String(), Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-it", ActorID: "agent-it"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream, Database: database, Mount: "database", Role: "readonly"}},
		Leases:    minter,
	})
	go func() { _ = broker.Serve(ln) }()
	defer func() { _ = broker.Shutdown(context.Background()) }()

	// The agent connects through the proxy with its Agent Vault token as the
	// password and NO database credential. sslmode=prefer exercises the proxy's
	// SSL-decline path.
	agentDSN := fmt.Sprintf("postgres://agent:agent-vault-token@%s/%s?sslmode=prefer", ln.Addr().String(), database)
	agent, err := pgx.Connect(ctx, agentDSN)
	if err != nil {
		t.Fatalf("agent connect through proxy: %v", err)
	}

	var whoami string
	if err := agent.QueryRow(ctx, "SELECT current_user").Scan(&whoami); err != nil {
		t.Fatalf("SELECT current_user: %v", err)
	}
	if whoami != roleName {
		t.Fatalf("connected as %q, want the Vault-minted role %q", whoami, roleName)
	}

	var count int
	if err := agent.QueryRow(ctx, "SELECT count(*) FROM customers").Scan(&count); err != nil {
		t.Fatalf("SELECT count(*): %v", err)
	}
	if count < 1 {
		t.Fatalf("expected the relayed query to return demo rows, got count=%d", count)
	}
	t.Logf("agent ran queries as Vault-minted role %q, saw %d customer rows", whoami, count)

	// A normal driver's cancellation must stop the running query without
	// disconnecting the session or minting a second database credential.
	queryDone := make(chan error, 1)
	go func() { _, err := agent.Exec(ctx, "SELECT pg_sleep(20)"); queryDone <- err }()
	waitFor(t, 3*time.Second, func() bool {
		var running bool
		err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND query='SELECT pg_sleep(20)' AND state='active')", roleName).Scan(&running)
		return err == nil && running
	}, "sleep query did not start")
	if err := agent.PgConn().CancelRequest(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-queryDone:
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
			t.Fatalf("expected query cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel request did not stop query")
	}
	if err := agent.QueryRow(ctx, "SELECT 1").Scan(&count); err != nil {
		t.Fatalf("session not reusable after cancel: %v", err)
	}
	if minter.mintCallCount() != 1 {
		t.Fatal("cancellation minted another credential")
	}

	_ = agent.Close(ctx)
	waitFor(t, 3*time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "lease not revoked after agent disconnect")
}

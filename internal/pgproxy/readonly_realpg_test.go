//go:build realpg

package pgproxy

// Read-only logins against a real PostgreSQL. Requires AV_TEST_PG_POOL_ADMIN,
// an admin DSN for a disposable server, as the pooled tests do. The test
// creates a login that can read but holds the TEMP privilege PUBLIC has by
// default, and proves the broker, not the database, refuses temporary objects.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRealPostgres_ReadOnlyLoginRefusesTemporaryObjects(t *testing.T) {
	dsn := os.Getenv("AV_TEST_PG_POOL_ADMIN")
	if dsn == "" {
		t.Skip("set AV_TEST_PG_POOL_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	u, _ := url.Parse(dsn)
	role, pw := "ro_"+randomHex(4), randomHex(16)
	table := "ro_items_" + randomHex(4)
	for _, sql := range []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, pw),
		fmt.Sprintf("CREATE TABLE %s (id int)", table),
		fmt.Sprintf("INSERT INTO %s VALUES (1), (2)", table),
		fmt.Sprintf("GRANT SELECT ON %s TO %s", table, role),
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = admin.Exec(c, fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s'", role))
		_, _ = admin.Exec(c, "DROP TABLE IF EXISTS "+table)
		_, _ = admin.Exec(c, "DROP ROLE IF EXISTS "+role)
	})
	tempObjects := func() int {
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = $1 AND c.relpersistence = 't'", role).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	broker := func(readOnly bool, pool *PoolOptions) string {
		lease := &Lease{ID: "lease-" + randomHex(4), Username: role, Password: pw, ExpiresAt: time.Now().Add(time.Hour)}
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
			Databases: &fakeResolver{svc: &DatabaseService{Name: "core", Addr: u.Host, Database: u.Path[1:], Mount: "database", Role: "staging.us.crunchy.core-readonly", SSLMode: "disable", ReadOnly: readOnly}},
			Leases:    &fakeMinter{lease: lease},
			Pool:      pool,
		})
		return addr
	}
	connect := func(addr string) *pgx.Conn {
		host, port, _ := net.SplitHostPort(addr)
		conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=workload password=agent-token dbname=core sslmode=disable", host, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return fmt.Sprint(err)
	}

	// Control: the database itself lets this login create a temporary table,
	// so any refusal below is the broker's.
	control := connect(broker(false, nil))
	if _, err := control.Exec(ctx, "CREATE TEMP TABLE scratch (id int)"); err != nil {
		t.Fatalf("control: the database refused a temporary table itself: %v", err)
	}
	if n := tempObjects(); n != 1 {
		t.Fatalf("control created %d temporary objects, want 1", n)
	}
	_ = control.Close(ctx)
	waitFor(t, 5*time.Second, func() bool { return tempObjects() == 0 }, "control session's temporary table dropped")

	attempts := []string{
		"CREATE TEMP TABLE scratch (id int)",
		"CREATE TEMPORARY VIEW v AS SELECT 1",
		"CREATE TEMP SEQUENCE s",
		"SELECT * INTO TEMP scratch FROM " + table,
		"CREATE TABLE pg_temp.scratch (id int)",
		"DO $$ BEGIN EXECUTE 'CREATE TEMP' || 'ORARY TABLE scratch (id int)'; END $$",
		"SELECT set_config('search_path', 'pg_' || 'temp', false)",
		"SET standard_conforming_strings = off",
	}

	t.Run("pooled", func(t *testing.T) {
		conn := connect(broker(true, &PoolOptions{QueueFactor: 10}))
		for _, sql := range attempts {
			if _, err := conn.Exec(ctx, sql); code(err) != "25006" {
				t.Fatalf("%q answered %v, want 25006", sql, err)
			}
		}
		var n int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 2 {
			t.Fatalf("read after refusals: %d %v", n, err)
		}
		if n := tempObjects(); n != 0 {
			t.Fatalf("%d temporary objects exist", n)
		}
	})

	t.Run("unpooled", func(t *testing.T) {
		addr := broker(true, nil)
		for _, sql := range attempts {
			conn := connect(addr)
			var n int
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 2 {
				t.Fatalf("read before %q: %d %v", sql, n, err)
			}
			if _, err := conn.Exec(ctx, sql); code(err) != "25006" {
				t.Fatalf("%q answered %v, want 25006", sql, err)
			}
			// The refusal ends the session.
			if err := conn.Ping(ctx); err == nil {
				t.Fatalf("session survived the refusal of %q", sql)
			}
		}
		if n := tempObjects(); n != 0 {
			t.Fatalf("%d temporary objects exist", n)
		}
	})
}

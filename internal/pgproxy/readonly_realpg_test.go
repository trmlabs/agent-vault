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
	"github.com/jackc/pgx/v5/pgproto3"
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
		`SELECT "set_config"('search_path', 'pg' || '_temp', false)`,
		`SELECT "pg_catalog"."set_config"('search_path', 'pg' || '_temp', false)`,
		`UPDATE "pg_settings" SET setting = 'pg' || '_temp' WHERE name = 'search_path'`,
		"CREATE TABLE t (x int)",
		"SET default_transaction_read_only = off",
		"BEGIN READ WRITE",
	}

	// What the internal API sends through Sequelize and node-postgres, on a
	// read-only login, pooled and not.
	reads := func(t *testing.T, conn *pgx.Conn) {
		t.Helper()
		for _, sql := range []string{
			"SET client_min_messages TO warning;SET TIME ZONE INTERVAL '+00:00' HOUR TO MINUTE;",
			"WITH ranges AS (SELECT pg_range.rngtypid, pg_type.typname AS rngtypname, pg_type.typarray AS rngtyparray, pg_range.rngsubtype FROM pg_range " +
				"LEFT OUTER JOIN pg_type ON pg_type.oid = pg_range.rngtypid) SELECT pg_type.typname, pg_type.typtype, pg_type.oid, pg_type.typarray, " +
				"ranges.rngtypname, ranges.rngtypid, ranges.rngtyparray FROM pg_type LEFT OUTER JOIN ranges ON pg_type.oid = ranges.rngsubtype WHERE (pg_type.typtype IN('b', 'e'));",
			"START TRANSACTION; SELECT count(*) FROM " + table + "; COMMIT;",
		} {
			if _, err := conn.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatalf("read path %q: %v", sql[:min(len(sql), 40)], err)
			}
		}
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM "`+table+`" WHERE "id" > $1`, 0).Scan(&n); err != nil || n != 2 {
			t.Fatalf("parameterized read: %d %v", n, err)
		}
		var readOnly string
		if err := conn.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
			t.Fatalf("default_transaction_read_only = %q %v, want on", readOnly, err)
		}
	}

	t.Run("pooled", func(t *testing.T) {
		conn := connect(broker(true, &PoolOptions{QueueFactor: 10}))
		reads(t, conn)
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
		reads(t, connect(addr))
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

	// Read-write pooled: an encoding change is refused, and one the classifier
	// cannot see (set_config with a computed name) ends the session when the
	// server reports it, before the next statement is read.
	t.Run("read-write pooled", func(t *testing.T) {
		addr := broker(false, &PoolOptions{QueueFactor: 10})
		conn := connect(addr)
		for _, sql := range []string{"SET client_encoding TO 'SJIS'", "SET NAMES 'BIG5'", "SET standard_conforming_strings = off"} {
			if _, err := conn.Exec(ctx, sql); code(err) != "42501" {
				t.Fatalf("%q answered %v, want 42501", sql, err)
			}
		}
		_, _ = conn.Exec(ctx, "SELECT set_config('standard_conforming_' || 'strings', 'off', false)")
		if err := conn.Ping(ctx); err == nil {
			t.Fatal("session survived standard_conforming_strings off")
		}
		var defaults int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_db_role_setting WHERE setrole = (SELECT oid FROM pg_roles WHERE rolname = $1)", role).Scan(&defaults); err != nil || defaults != 0 {
			t.Fatalf("role defaults %d %v", defaults, err)
		}
		// Pipelined: the change and a statement hidden from the broker's
		// lexer arrive together. The second is held until the first is
		// answered, and the answer's ParameterStatus ends the session, so
		// the hidden ALTER ROLE never runs.
		raw := openAgentSession(t, addr, "agent-token", "core")
		raw.fe.Send(&pgproto3.Query{String: "SELECT set_config('standard_conforming_' || 'strings', 'off', false)"})
		raw.fe.Send(&pgproto3.Query{String: `SELECT 'x\' , ' ; ALTER ROLE CURRENT_USER SET work_mem = 7777; --'`})
		if err := raw.fe.Flush(); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := raw.fe.Receive(); err != nil {
				break
			}
		}
		raw.close()
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_db_role_setting WHERE setrole = (SELECT oid FROM pg_roles WHERE rolname = $1)", role).Scan(&defaults); err != nil || defaults != 0 {
			t.Fatalf("pipelined hidden ALTER ROLE ran: role defaults %d %v", defaults, err)
		}
		next := connect(addr)
		var scs string
		if err := next.QueryRow(ctx, "SHOW standard_conforming_strings").Scan(&scs); err != nil || scs != "on" {
			t.Fatalf("next session standard_conforming_strings = %q %v", scs, err)
		}
	})
}

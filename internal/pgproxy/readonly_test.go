package pgproxy

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// readOnlyRefuses is what a read-only session refuses on its first text.
func readOnlyRefuses(sql string) bool {
	lexer, _ := changesLexer(sql, false)
	return lexer || !readOnlyAllowed(sql)
}

// sequelizeConnect is what Sequelize 6 sends on every new connection: the
// session settings, then its type lookup.
const (
	sequelizeConnect = "SET client_min_messages TO warning;SET TIME ZONE INTERVAL '+00:00' HOUR TO MINUTE;"
	sequelizeTypes   = "WITH ranges AS (  SELECT pg_range.rngtypid, pg_type.typname AS rngtypname,         pg_type.typarray AS rngtyparray, pg_range.rngsubtype    FROM pg_range LEFT OUTER JOIN pg_type ON pg_type.oid = pg_range.rngtypid)SELECT pg_type.typname, pg_type.typtype, pg_type.oid, pg_type.typarray,       ranges.rngtypname, ranges.rngtypid, ranges.rngtyparray  FROM pg_type LEFT OUTER JOIN ranges ON pg_type.oid = ranges.rngsubtype WHERE (pg_type.typtype IN('b', 'e'));"
)

func TestReadOnlyAllowlist(t *testing.T) {
	for sql, want := range map[string]bool{
		// What a read-only login does, including the internal API through
		// Sequelize and node-postgres: allowed.
		sequelizeConnect:                      false,
		sequelizeTypes:                        false,
		"SET standard_conforming_strings=on;": false, // Sequelize, when the server reports otherwise
		"SELECT 1":                            false,
		"SELECT temp FROM weather":            false, // a column named temp
		"SELECT * FROM t WHERE label = 'create temp table'": false, // keywords only inside a string
		"SELECT \"temp\" FROM t":                            false,
		"SELECT \"id\", \"name\" FROM \"public\".\"users\" AS \"users\" WHERE \"users\".\"id\" = $1 LIMIT 1": false,
		"WITH x AS (SELECT 1) SELECT * FROM x":       false,
		"VALUES (1), (2)":                            false,
		"TABLE t":                                    false,
		"SHOW client_encoding":                       false,
		"EXPLAIN SELECT * FROM t":                    false,
		"EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM t": false,
		"START TRANSACTION; SELECT 1; COMMIT;":       false,
		"BEGIN READ ONLY; SAVEPOINT a; SELECT 1; RELEASE SAVEPOINT a; ROLLBACK TO SAVEPOINT a; COMMIT": false,
		"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ":                                              false,
		"SET search_path TO app, public":                                                               false,
		"SET LOCAL statement_timeout = 5000":                                                           false,
		"SET application_name = 'probe'":                                                               false,
		"RESET statement_timeout":                                                                      false,
		"DECLARE c CURSOR FOR SELECT 1; FETCH 10 FROM c; CLOSE c":                                      false,
		"SELECT E'a\\nb'": false,
		"":                false,
		// Reported bypasses: quoted names and computed values.
		`SELECT "set_config"('search_path', 'pg' || '_temp', false)`:                    true,
		`SELECT "pg_catalog"."set_config"('search_path', 'pg' || '_temp', false)`:       true,
		`UPDATE "pg_settings" SET setting = 'pg' || '_temp' WHERE name = 'search_path'`: true,
		`SELECT "SET_CONFIG"('a', 'b', false)`:                                          true,
		"SELECT set_config('search_path', 'pg_'||'temp', false)":                        true,
		"SELECT * FROM pg_settings":                                                     true, // named at all
		// Temporary objects, however spelled.
		"CREATE TEMP TABLE scratch (id int)":                             true,
		"create temporary table scratch (id int)":                        true,
		"CREATE GLOBAL TEMPORARY TABLE x (id int)":                       true,
		"CREATE OR REPLACE TEMP VIEW v AS SELECT 1":                      true,
		"CREATE TEMPORARY SEQUENCE s":                                    true,
		"/* hi */ CREATE/**/TEMP TABLE x (id int)":                       true,
		"SELECT 1; CREATE TEMP TABLE x (id int)":                         true,
		"SELECT * INTO TEMP scratch FROM t":                              true,
		"SELECT * INTO scratch FROM t":                                   true,
		"EXPLAIN ANALYZE CREATE TEMP TABLE x AS SELECT 1":                true,
		"CREATE TABLE t (x int)":                                         true,
		"CREATE TABLE \"pg_temp\".x (id int)":                            true,
		"CREATE TABLE PG_TEMP_3.x (id int)":                              true,
		"SET search_path TO pg_temp, public":                             true,
		"SET search_path = 'pg_temp'":                                    true,
		"CREATE TABLE U&\"pg\\005ftemp\".x (id int)":                     true,
		"SET search_path = E'pg\\137temp'":                               true,
		"SET SCHEMA E'pg\\137temp'":                                      true,
		"DO $$ BEGIN EXECUTE 'CREATE TEMP' || 'ORARY TABLE x()'; END $$": true,
		// Writes and anything else outside the allowlist.
		"INSERT INTO t VALUES (1)": true,
		"UPDATE t SET x = 1":       true,
		"DELETE FROM t":            true,
		"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d": true,
		"SELECT * FROM t FOR UPDATE":                            true,
		"EXPLAIN ANALYZE INSERT INTO t VALUES (1)":              true,
		"EXPLAIN DELETE FROM t":                                 true,
		"BEGIN READ WRITE":                                      true,
		"START TRANSACTION READ WRITE":                          true,
		"SET TRANSACTION READ WRITE":                            true,
		"SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE": true,
		"SET default_transaction_read_only = off":               true,
		"SET transaction_read_only = off":                       true,
		"RESET ALL":                                             true,
		"RESET default_transaction_read_only":                   true,
		"SET ROLE postgres":                                     true,
		"SET SESSION AUTHORIZATION postgres":                    true,
		"SET work_mem = '1GB'":                                  true,
		"LISTEN jobs":                                           true,
		"CALL refresh_things()":                                 true,
		"COPY t TO STDOUT":                                      true,
		"PREPARE p AS SELECT 1":                                 true,
		"DISCARD ALL":                                           true,
		"ALTER ROLE CURRENT_USER PASSWORD 'x'":                  true,
		"SET standard_conforming_strings = off":                 true,
		"SET client_encoding TO 'SJIS'":                         true,
		"SELECT 'unterminated":                                  true,
		"SELECT 1 /* unterminated":                              true,
	} {
		if got := readOnlyRefuses(sql); got != want {
			t.Errorf("read-only refuses %q = %v, want %v", sql, got, want)
		}
	}
}

// Every pooled session, read-write included, refuses a change to how the
// server reads text: only on and UTF8, and only before any other statement.
func TestChangesLexer(t *testing.T) {
	for _, tc := range []struct {
		sql     string
		started bool
		refuse  bool
	}{
		{"SET standard_conforming_strings=on;", false, false},
		{"set standard_conforming_strings to 'on'", false, false},
		{"SET client_encoding TO 'UTF8'", false, false},
		{"SET NAMES 'utf8'", false, false},
		{"SET standard_conforming_strings=on;SET client_min_messages TO warning;", false, false},
		{"SET client_min_messages TO warning; SHOW client_encoding; RESET client_encoding", true, false},
		{"SELECT 'SET client_encoding TO SJIS'", true, false},
		{"SET standard_conforming_strings = off", false, true},
		{"SET standard_conforming_strings = 'off'", false, true},
		{"SET standard_conforming_strings TO DEFAULT", false, true},
		{"SET LOCAL standard_conforming_strings = on", false, true},
		{"SET client_encoding TO 'SJIS'", false, true},
		{"SET client_encoding TO 'BIG5'", false, true},
		{"SET NAMES 'SJIS'", false, true},
		{"SET NAMES 'BIG5'", false, true},
		{"SET SESSION client_encoding TO 'LATIN1'", false, true},
		{"SET standard_conforming_strings = on", true, true},     // after another statement
		{"SELECT 1; SET client_encoding TO 'UTF8'", false, true}, // in the same text
		{"SET client_encoding = 'UTF8'; SET client_encoding = 'SJIS'", false, true},
	} {
		if got, _ := changesLexer(tc.sql, tc.started); got != tc.refuse {
			t.Errorf("changesLexer(%q, started=%v) = %v, want %v", tc.sql, tc.started, got, tc.refuse)
		}
	}
	if _, next := changesLexer("SET client_encoding TO 'UTF8'", false); next {
		t.Error("a safe encoding SET counted as another statement")
	}
	if _, next := changesLexer("SELECT 1", false); !next {
		t.Error("a query did not start the session")
	}
}

func readOnlyBroker(t *testing.T, readOnly bool, pool *PoolOptions) (*fakeUpstream, string, *recordingAudit) {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &recordingAudit{}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "staging.us.crunchy.core-readonly", SSLMode: "disable", MaxConns: 2, ReadOnly: readOnly}},
		Leases:    &fakeMinter{lease: lease},
		Pool:      pool,
		Audit:     audit,
	})
	return upstream, addr, audit
}

func (fu *fakeUpstream) received() []string {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	return append([]string(nil), fu.queries...)
}

func deniedOutcomes(audit *recordingAudit) []string {
	var out []string
	for _, e := range audit.recorded() {
		if e.Event == "denied" {
			out = append(out, e.Outcome)
		}
	}
	return out
}

// Unpooled, a read-only login's statements are classified before they are
// relayed: a temporary table never reaches the database, the client reads a
// FATAL refusal, and the refusal is audited.
func TestReadOnlyUnpooledRefusesTemporaryTables(t *testing.T) {
	upstream, addr, audit := readOnlyBroker(t, true, nil)
	if got, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT current_user"); err != nil || got == "" {
		t.Fatalf("read-only SELECT: %q, %v", got, err)
	}
	_, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "CREATE TEMP TABLE scratch (id int)")
	if err == nil || !strings.Contains(err.Error(), "(25006)") || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("temporary table answered %v, want the 25006 read-only refusal", err)
	}
	for _, q := range upstream.received() {
		if q == "CREATE TEMP TABLE scratch (id int)" {
			t.Fatalf("refused statement reached the database: %q", q)
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		for _, o := range deniedOutcomes(audit) {
			if o == "read_only" {
				return true
			}
		}
		return false
	}, "the refusal is audited as read_only")
}

// A fast-path FunctionCall names its function by OID, so a read-only login
// cannot use it to call set_config unseen.
func TestReadOnlyUnpooledRefusesFunctionCall(t *testing.T) {
	_, addr, _ := readOnlyBroker(t, true, nil)
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	s.fe.Send(&pgproto3.FunctionCall{Function: 2078, ResultFormatCode: 0})
	if err := s.fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := s.fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := msg.(*pgproto3.ErrorResponse); !ok || e.Code != "25006" || e.Severity != "FATAL" {
		t.Fatalf("FunctionCall answered %#v, want a FATAL 25006", msg)
	}
}

// A read-write login is unchanged: its statements pass through untouched.
func TestReadWriteUnpooledKeepsTemporaryTables(t *testing.T) {
	upstream, addr, _ := readOnlyBroker(t, false, nil)
	if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "CREATE TEMP TABLE scratch (id int)"); err != nil {
		t.Fatal(err)
	}
	if got := upstream.received(); len(got) != 1 || got[0] != "CREATE TEMP TABLE scratch (id int)" {
		t.Fatalf("upstream received %q", got)
	}
}

// A startup search path naming pg_temp would make an unqualified CREATE
// TABLE temporary, so a read-only login with one is refused at startup.
func TestReadOnlyRefusesTemporarySearchPathAtStartup(t *testing.T) {
	for _, pool := range []*PoolOptions{nil, {QueueFactor: 20}} {
		_, addr, _ := readOnlyBroker(t, true, pool)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fe := pgproto3.NewFrontend(conn, conn)
		fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters: map[string]string{"user": "agent", "database": "appdb", "search_path": "PG_TEMP, public"}})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}
		code := ""
		for code == "" {
			msg, err := fe.Receive()
			if err != nil {
				t.Fatalf("pool=%v: %v", pool != nil, err)
			}
			switch m := msg.(type) {
			case *pgproto3.AuthenticationCleartextPassword:
				fe.Send(&pgproto3.PasswordMessage{Password: "agent-vault-token"})
				_ = fe.Flush()
			case *pgproto3.ErrorResponse:
				code = m.Code
			case *pgproto3.ReadyForQuery:
				t.Fatalf("pool=%v: session admitted with pg_temp on its search path", pool != nil)
			}
		}
		_ = conn.Close()
		if code != "25006" {
			t.Fatalf("pool=%v: answered %s, want 25006", pool != nil, code)
		}
	}
}

// Pooled, the refusal is an ERROR and the session stays usable.
func TestReadOnlyPooledRefusesTemporaryTables(t *testing.T) {
	upstream, addr, audit := readOnlyBroker(t, true, &PoolOptions{QueueFactor: 20})
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	for _, sql := range []string{"CREATE TEMP TABLE scratch (id int)", "SELECT * INTO TEMP scratch FROM t", "DO $$ BEGIN NULL; END $$"} {
		if code := queryCode(t, s, sql); code != "25006" {
			t.Fatalf("%q answered %q, want 25006", sql, code)
		}
	}
	if code := queryCode(t, s, "SELECT 1"); code != "" {
		t.Fatalf("session unusable after the refusal: %q", code)
	}
	// The broker's own check-in query names pg_my_temp_schema, so match the
	// refused statements exactly.
	refused := map[string]bool{"CREATE TEMP TABLE scratch (id int)": true, "SELECT * INTO TEMP scratch FROM t": true, "DO $$ BEGIN NULL; END $$": true}
	for _, q := range upstream.received() {
		if refused[q] {
			t.Fatalf("refused statement reached the database: %q", q)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return len(deniedOutcomes(audit)) == 3 }, "three audited refusals")
	// A FunctionCall gets its own ReadyForQuery, as the server would send.
	s.fe.Send(&pgproto3.FunctionCall{Function: 2078})
	if err := s.fe.Flush(); err != nil {
		t.Fatal(err)
	}
	code := ""
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if e, ok := msg.(*pgproto3.ErrorResponse); ok {
			code = e.Code
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if code != "25006" {
		t.Fatalf("FunctionCall answered %q, want 25006", code)
	}
}

// Read-write pooled sessions are unchanged.
func TestReadWritePooledKeepsTemporaryTables(t *testing.T) {
	_, addr, _ := readOnlyBroker(t, false, &PoolOptions{QueueFactor: 20})
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	if code := queryCode(t, s, "CREATE TEMP TABLE scratch (id int)"); code != "" {
		t.Fatalf("read-write temporary table answered %q", code)
	}
}

// The tracker follows message framing however the stream is split.
func TestFrameTrackerFollowsSplitMessages(t *testing.T) {
	var stream []byte
	for _, m := range []pgproto3.BackendMessage{
		&pgproto3.DataRow{Values: [][]byte{bytes.Repeat([]byte("x"), 300)}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	} {
		var err error
		if stream, err = m.Encode(stream); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{1, 2, 4, 5, 7, 64, len(stream)} {
		var out bytes.Buffer
		tr := &frameTracker{w: &out}
		for i := 0; i < len(stream); i += size {
			_, _ = tr.Write(stream[i:min(i+size, len(stream))])
			if i+size < len(stream) && i+size == 5 && tr.atBoundary() {
				t.Fatalf("size %d: boundary inside a header", size)
			}
		}
		if !tr.atBoundary() || !bytes.Equal(out.Bytes(), stream) {
			t.Fatalf("size %d: boundary=%v, copied %d of %d bytes", size, tr.atBoundary(), out.Len(), len(stream))
		}
		tr = &frameTracker{w: &out}
		_, _ = tr.Write(stream[:len(stream)-1])
		if tr.atBoundary() {
			t.Fatalf("size %d: boundary reported mid-message", size)
		}
	}
}

// A read-write pooled session refuses a mid-session encoding change, so the
// broker's lexer and the server always read text the same way, and keeps the
// session open.
func TestReadWritePooledRefusesEncodingChanges(t *testing.T) {
	upstream, addr, audit := readOnlyBroker(t, false, &PoolOptions{QueueFactor: 20})
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	if code := queryCode(t, s, "SET standard_conforming_strings=on"); code != "" {
		t.Fatalf("connect-time safe SET answered %q", code)
	}
	for _, sql := range []string{"SET standard_conforming_strings = off", "SET client_encoding TO 'SJIS'", "SET NAMES 'BIG5'"} {
		if code := queryCode(t, s, sql); code != "42501" {
			t.Fatalf("%q answered %q, want 42501", sql, code)
		}
	}
	if code := queryCode(t, s, "CREATE TEMP TABLE scratch (id int)"); code != "" {
		t.Fatalf("read-write session lost a temporary table: %q", code)
	}
	// Even the safe value is refused once another statement has run.
	if code := queryCode(t, s, "SET client_encoding TO 'UTF8'"); code != "42501" {
		t.Fatalf("late encoding SET answered %q, want 42501", code)
	}
	for _, q := range upstream.received() {
		if strings.Contains(q, "SJIS") || strings.Contains(q, "BIG5") || strings.Contains(q, "= off") {
			t.Fatalf("refused statement reached the database: %q", q)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return len(deniedOutcomes(audit)) == 4 }, "four audited refusals")
}

func TestUnsafeLexerParameter(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		unsafe      bool
	}{
		{"standard_conforming_strings", "on", false},
		{"standard_conforming_strings", "off", true},
		{"client_encoding", "UTF8", false},
		{"client_encoding", "SJIS", true},
		{"client_encoding", "BIG5", true},
		{"TimeZone", "UTC", false},
	} {
		if got := unsafeLexerParameter(tc.name, tc.value); got != tc.unsafe {
			t.Errorf("%s=%s: unsafe %v, want %v", tc.name, tc.value, got, tc.unsafe)
		}
	}
}

// Inside one unsynced extended-protocol batch, a statement with a backslash
// cannot follow an Execute: there is no answer to wait for that would show
// whether the Execute changed how the server reads it.
func TestPooledRefusesBackslashAfterUnsyncedExecute(t *testing.T) {
	_, addr, _ := readOnlyBroker(t, false, &PoolOptions{QueueFactor: 20})
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	s.fe.Send(&pgproto3.Parse{Query: "SELECT 1"})
	s.fe.Send(&pgproto3.Bind{})
	s.fe.Send(&pgproto3.Execute{})
	s.fe.Send(&pgproto3.Parse{Query: `SELECT 'a\b'`})
	s.fe.Send(&pgproto3.Sync{})
	if err := s.fe.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			t.Fatalf("session ended without the refusal: %v", err)
		}
		if e, ok := msg.(*pgproto3.ErrorResponse); ok {
			if e.Code != "0A000" {
				t.Fatalf("refusal %s %s", e.Code, e.Message)
			}
			return
		}
	}
}

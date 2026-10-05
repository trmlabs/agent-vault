package pgproxy

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestCreatesTemporaryFailsClosed(t *testing.T) {
	for sql, want := range map[string]bool{
		// What a read-only login does: unaffected.
		"SELECT 1":                 false,
		"SELECT temp FROM weather": false, // a column named temp
		"SELECT * FROM t WHERE label = 'create temp table'": false, // keywords only inside a string
		"SELECT \"temp\" FROM t":                            false,
		"WITH x AS (SELECT 1) SELECT * FROM x":              false,
		"SET search_path TO app, public":                    false,
		"SET LOCAL statement_timeout = 5000":                false,
		"SHOW client_encoding":                              false,
		"SELECT E'a\\nb'":                                   false, // escapes are fine away from a search path
		"BEGIN READ ONLY; SELECT 1; COMMIT":                 false,
		"EXPLAIN SELECT * FROM t":                           false,
		"DECLARE c CURSOR FOR SELECT 1":                     false,
		"":                                                  false,
		// Temporary objects, however spelled.
		"CREATE TEMP TABLE scratch (id int)":                             true,
		"create temporary table scratch (id int)":                        true,
		"CREATE GLOBAL TEMPORARY TABLE x (id int)":                       true,
		"CREATE LOCAL TEMP TABLE x (id int)":                             true,
		"CREATE TEMP VIEW v AS SELECT 1":                                 true,
		"CREATE OR REPLACE TEMP VIEW v AS SELECT 1":                      true,
		"CREATE TEMPORARY SEQUENCE s":                                    true,
		"CREATE TEMP TABLE x AS SELECT 1":                                true,
		"/* hi */ CREATE/**/TEMP TABLE x (id int)":                       true,
		"SELECT 1; CREATE TEMP TABLE x (id int)":                         true,
		"SELECT * INTO TEMP scratch FROM t":                              true,
		"SELECT * INTO LOCAL TEMPORARY scratch FROM t":                   true,
		"EXPLAIN ANALYZE CREATE TEMP TABLE x AS SELECT 1":                true,
		"CREATE TABLE pg_temp.x (id int)":                                true,
		"CREATE TABLE \"pg_temp\".x (id int)":                            true,
		"CREATE TABLE PG_TEMP_3.x (id int)":                              true,
		"CREATE FUNCTION pg_temp.f() RETURNS int AS 'SELECT 1'":          true,
		"SET search_path TO pg_temp, public":                             true,
		"SET search_path = 'pg_temp'":                                    true,
		"CREATE TABLE U&\"pg\\005ftemp\".x (id int)":                     true,
		"SET search_path = E'pg\\137temp'":                               true,
		"SET SCHEMA E'pg\\137temp'":                                      true,
		"SELECT set_config('search_path', 'pg_'||'temp', false)":         true,
		"SELECT pg_catalog.set_config('a', 'b', false)":                  true,
		"UPDATE pg_settings SET setting = 'x' WHERE name = 'y'":          true,
		"DO $$ BEGIN EXECUTE 'CREATE TEMP' || 'ORARY TABLE x()'; END $$": true,
		"do language plpgsql $$ BEGIN NULL; END $$":                      true,
		"SET standard_conforming_strings = off":                          true,
		"SET SESSION client_encoding TO 'SJIS'":                          true,
		"SET NAMES 'SJIS'":                                               true,
		"SELECT 'unterminated":                                           true,
		"SELECT 1 /* unterminated":                                       true,
	} {
		if got := createsTemporary(sql); got != want {
			t.Errorf("createsTemporary(%q) = %v, want %v", sql, got, want)
		}
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
		if strings.Contains(strings.ToLower(q), "temp") {
			t.Fatalf("refused statement reached the database: %q", q)
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		for _, o := range deniedOutcomes(audit) {
			if o == "read_only_temp" {
				return true
			}
		}
		return false
	}, "the refusal is audited as read_only_temp")
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
	for _, q := range upstream.received() {
		if strings.Contains(strings.ToLower(q), "temp") || strings.HasPrefix(q, "DO") {
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

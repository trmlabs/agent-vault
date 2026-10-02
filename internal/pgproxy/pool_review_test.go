package pgproxy

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func pooledBroker(t *testing.T, lease *Lease) (*fakeUpstream, string) {
	t.Helper()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 2}},
		Leases:    &fakeMinter{lease: lease},
		Pool:      &PoolOptions{QueueFactor: 20},
	})
	return upstream, addr
}

// queryCode runs one query and returns the SQLSTATE it ended with ("" for
// success), reading through ReadyForQuery so the session stays in step.
func queryCode(t *testing.T, s *agentSession, sql string) string {
	t.Helper()
	s.fe.Send(&pgproto3.Query{String: sql})
	if err := s.fe.Flush(); err != nil {
		t.Fatal(err)
	}
	code := ""
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			code = m.Code
		case *pgproto3.ReadyForQuery:
			return code
		}
	}
}

// A role or database default set through the shared pool login would reach
// every later client of it, so the statement never reaches the server.
func TestPooledSessionRefusesRoleChanges(t *testing.T) {
	_, addr := pooledBroker(t, newLease())
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	if code := queryCode(t, s, "ALTER ROLE CURRENT_USER SET search_path = evil, public"); code != "42501" {
		t.Fatalf("role change answered %q, want 42501", code)
	}
	if code := queryCode(t, s, "SELECT 1"); code != "" {
		t.Fatalf("session unusable after the refusal: %q", code)
	}
}

// Every pooled server connection is opened with the broker's idle-in-
// transaction limit, so a client cannot sit on one inside a transaction.
func TestPooledServerConnectionsCarryTheIdleInTransactionLimit(t *testing.T) {
	upstream, addr := pooledBroker(t, newLease())
	if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	upstream.mu.Lock()
	got := upstream.lastIdleTxn
	upstream.mu.Unlock()
	if got != "300000" {
		t.Fatalf("idle_in_transaction_session_timeout = %q, want 300000 (5m)", got)
	}
}

// At its credential's expiry the broker closes the server connection itself,
// so a session holding one ends even if the Vault role's revocation does not
// terminate backends.
func TestPooledSessionEndsWhenItsCredentialExpires(t *testing.T) {
	lease := newLease()
	lease.ExpiresAt = time.Now().Add(3 * time.Second)
	_, addr := pooledBroker(t, lease)
	s := openAgentSession(t, addr, "agent-vault-token", "appdb")
	defer s.close()
	// Session state pins the server connection to this client.
	if code := queryCode(t, s, "SET work_mem = '8MB'"); code != "" {
		t.Fatalf("SET answered %q", code)
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 512)
	for {
		if _, err := s.conn.Read(buf); err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("pinned session outlived its credential")
			}
			return
		}
	}
}

// Named prepared statements are capped per session by count and by bytes.
func TestPooledSessionCapsPreparedStatements(t *testing.T) {
	s := &pooledSession{statements: map[string]clientStatement{}}
	for i := range maxSessionStatements {
		name := "s" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
		s.statements[name] = clientStatement{query: "SELECT 1"}
		s.statementBytes += len("SELECT 1")
	}
	if err := s.refuse(&pgproto3.Parse{Name: "one-more", Query: "SELECT 2"}, "SELECT 2"); !errors.Is(err, errStatementLimit) {
		t.Fatalf("statement over the count cap: %v", err)
	}
	var existing string
	for name := range s.statements {
		existing = name
		break
	}
	if err := s.refuse(&pgproto3.Parse{Name: existing, Query: "SELECT 3"}, "SELECT 3"); err != nil {
		t.Fatalf("replacing a statement counted as a new one: %v", err)
	}
	big := &pooledSession{statements: map[string]clientStatement{}}
	huge := strings.Repeat("x", maxSessionStatementBytes)
	if err := big.refuse(&pgproto3.Parse{Name: "huge", Query: huge + "y"}, huge); !errors.Is(err, errStatementLimit) {
		t.Fatalf("statement over the byte cap: %v", err)
	}
	if err := big.refuse(&pgproto3.Parse{Name: "", Query: huge + "y"}, ""); err != nil {
		t.Fatalf("unnamed statements are not stored and must not be capped: %v", err)
	}
}

// kill detaches the server connection under the session lock and closes it,
// so it can never have returned to the pool, and to another client, by the
// time its cancel is sent.
func TestKillDetachesAndClosesTheServerConnection(t *testing.T) {
	b := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, Leases: &fakeMinter{lease: newLease()}})
	t.Cleanup(b.pools.close)
	server, brokerSide := net.Pipe()
	client, clientSide := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	pool := &serverPool{svc: DatabaseService{Addr: "db.internal:5432"}}
	cred := &credential{lease: newLease(), conns: 1}
	conn := &serverConn{sess: &upstreamSession{conn: brokerSide}, cred: cred, pool: pool}
	cred.open = map[*serverConn]struct{}{conn: {}}
	s := &pooledSession{b: b, client: clientSide, conn: conn, cancel: &cancelTarget{active: true}}
	s.kill()
	if s.conn != nil {
		t.Fatal("kill left the server connection attached")
	}
	if len(pool.idle) != 0 || cred.conns != 0 || len(cred.open) != 0 {
		t.Fatalf("server connection returned to the pool: idle=%d conns=%d open=%d", len(pool.idle), cred.conns, len(cred.open))
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("server connection still open after kill")
	}
	if s.cancel.active {
		t.Fatal("cancel key still bound after kill")
	}
}

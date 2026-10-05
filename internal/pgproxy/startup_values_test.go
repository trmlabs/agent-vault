package pgproxy

import (
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// runAgentStartup completes agent authentication through the broker with the
// given startup parameters and returns once the broker reports ReadyForQuery.
// By then the fake upstream has recorded the startup message it received.
func runAgentStartup(t *testing.T, brokerAddr string, params map[string]string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", brokerAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("auth: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: "tok"})
			if err := fe.Flush(); err != nil {
				t.Fatalf("flush password: %v", err)
			}
		case *pgproto3.ReadyForQuery:
			return
		case *pgproto3.ErrorResponse:
			t.Fatalf("startup error %s: %s", m.Code, m.Message)
		}
	}
}

// TestBroker_BoundsForwardedStartupValues proves the broker bounds the value of
// a forwardable startup parameter, not only its key. An agent reaching the
// broker's PostgreSQL listener directly must not be able to clear a role-level
// statement_timeout (or smuggle options through any allowlisted key) with a
// value the relay would have refused. Invalid values are dropped, never sent.
func TestBroker_BoundsForwardedStartupValues(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	upstream.forbidParam = "search_path"
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Database: "db", Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:    minter,
	})

	for _, bad := range []string{"0", "-1", "30s", "abc -c role=admin"} {
		runAgentStartup(t, addr, map[string]string{
			"user": "agent", "database": "db",
			"statement_timeout": bad,
			"application_name":  "injected\nlog",
			"search_path":       "public\x01; -c role=admin",
		})
		upstream.mu.Lock()
		timeout, appName, forbidSeen := upstream.lastTimeout, upstream.lastAppNm, upstream.forbidSeen
		upstream.mu.Unlock()
		if timeout != "" {
			t.Errorf("statement_timeout %q reached the upstream as %q; want it dropped", bad, timeout)
		}
		if appName != "" {
			t.Errorf("control-character application_name reached the upstream as %q", appName)
		}
		if forbidSeen {
			t.Errorf("control-character search_path reached the upstream")
		}
	}

	runAgentStartup(t, addr, map[string]string{
		"user": "agent", "database": "db",
		"statement_timeout": "30000",
		"application_name":  "agent-under-test",
	})
	upstream.mu.Lock()
	timeout, appName := upstream.lastTimeout, upstream.lastAppNm
	upstream.mu.Unlock()
	if timeout != "30000" {
		t.Errorf("valid statement_timeout = %q at the upstream, want 30000", timeout)
	}
	if appName != "agent-under-test" {
		t.Errorf("valid application_name = %q at the upstream, want agent-under-test", appName)
	}
}

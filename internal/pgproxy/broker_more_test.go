package pgproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// agentSession is a live agent connection held open by a test.
type agentSession struct {
	conn net.Conn
	fe   *pgproto3.Frontend
}

func openAgentSession(t *testing.T, addr, token, database string) *agentSession {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": database}})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send startup: %v", err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("auth receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			goto ready
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: token})
			if err := fe.Flush(); err != nil {
				t.Fatalf("send token: %v", err)
			}
		case *pgproto3.ErrorResponse:
			t.Fatalf("unexpected auth error %s (%s)", m.Message, m.Code)
		}
	}
ready:
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("ready receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			t.Fatalf("startup error %s", er.Code)
		}
	}
	return &agentSession{conn: conn, fe: fe}
}

func (s *agentSession) query(q string) (string, error) {
	s.fe.Send(&pgproto3.Query{String: q})
	if err := s.fe.Flush(); err != nil {
		return "", err
	}
	var cell string
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			return "", err
		}
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			if len(m.Values) > 0 {
				cell = string(m.Values[0])
			}
		case *pgproto3.ReadyForQuery:
			return cell, nil
		case *pgproto3.ErrorResponse:
			return "", fmt.Errorf("query error %s", m.Code)
		}
	}
}

func (s *agentSession) close() {
	s.fe.Send(&pgproto3.Terminate{})
	_ = s.fe.Flush()
	_ = s.conn.Close()
}

// connectExpectCode drives the agent handshake and returns the SQLSTATE of the
// FATAL error the broker sends, or "OK" if it reached ready, or "" on transport
// failure.
func connectExpectCode(t *testing.T, addr, token, database string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": database}})
	if err := fe.Flush(); err != nil {
		return ""
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			return ""
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: token})
			if err := fe.Flush(); err != nil {
				return ""
			}
		case *pgproto3.ErrorResponse:
			return m.Code
		case *pgproto3.ReadyForQuery:
			return "OK"
		}
	}
}

func TestBroker_RefusesCleartextOverUnverifiedTLS(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstreamTLS(t, authCleartext, lease.Password, selfSignedTLSConfig(t))
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "require"}},
		Leases:    minter,
	})
	if code := connectExpectCode(t, addr, "tok", "appdb"); code != "08006" {
		t.Fatalf("unverified TLS must not receive password, got %s", code)
	}
}

func TestBroker_RefusesCleartextWithoutTLS(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authCleartext, lease.Password) // plaintext
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable"}},
		Leases:    minter,
	})
	// The broker must refuse to send the password in the clear -> upstream
	// connect fails -> the agent gets an 08006, and the (already minted) lease is
	// revoked.
	if code := connectExpectCode(t, addr, "tok", "appdb"); code != "08006" {
		t.Fatalf("expected 08006 (connection failure), got %q", code)
	}
	waitFor(t, 2*time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "lease not revoked after refused cleartext")
}

func TestBroker_TerminatesSessionOnExpiry(t *testing.T) {
	lease := &Lease{ID: "lease-exp", Username: "v-exp-1", Password: "pw", ExpiresAt: time.Now().Add(600 * time.Millisecond), Renewable: false}
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:    minter,
	})
	session := openAgentSession(t, addr, "tok", "appdb")
	if _, err := session.query("SELECT current_user"); err != nil {
		t.Fatalf("initial query should work: %v", err)
	}
	// A non-renewable lease that expires must terminate the live session so it
	// cannot outlive its credential.
	waitFor(t, 3*time.Second, func() bool {
		_, err := session.query("SELECT current_user")
		return err != nil
	}, "session was not terminated after the credential expired")
	waitFor(t, 2*time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "lease not revoked after expiry termination")
	session.close()
}

func TestBroker_RenewsBeforeExpiry(t *testing.T) {
	lease := &Lease{ID: "lease-renew", Username: "v-renew-1", Password: "pw", ExpiresAt: time.Now().Add(500 * time.Millisecond), Renewable: true}
	upstream := startFakeUpstream(t, authTrust, "")
	// Renew pushes expiry well into the future so the session stays alive.
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:             &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases:        &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:           minter,
		MinRenewInterval: 20 * time.Millisecond,
	})
	session := openAgentSession(t, addr, "tok", "appdb")
	defer session.close()
	// The renew loop must actually call Renew before expiry.
	waitFor(t, 2*time.Second, func() bool {
		minter.mu.Lock()
		defer minter.mu.Unlock()
		return minter.renewCalls >= 1
	}, "renew loop never renewed the lease")
	// And the session stays usable after the original TTL would have elapsed.
	time.Sleep(200 * time.Millisecond)
	if _, err := session.query("SELECT current_user"); err != nil {
		t.Fatalf("session should stay alive after renewal: %v", err)
	}
}

func TestBroker_ShutdownRevokesInFlight(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: lease}
	broker, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:    minter,
	})
	session := openAgentSession(t, addr, "tok", "appdb")
	defer session.close()
	// Shutdown must close the in-flight connection and revoke its lease.
	if err := broker.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if revoked := minter.revokedLeases(); len(revoked) != 1 || revoked[0] != lease.ID {
		t.Fatalf("shutdown did not revoke the in-flight lease: %v", revoked)
	}
}

func TestBroker_LeaseCapPerActor(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:              &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases:         &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:            minter,
		MaxLeasesPerActor: 1,
	})
	first := openAgentSession(t, addr, "tok", "appdb")
	defer first.close()
	// The actor already holds one live lease; a second concurrent session is
	// refused before minting.
	if code := connectExpectCode(t, addr, "tok", "appdb"); code != "53300" {
		t.Fatalf("expected 53300 (too many sessions), got %q", code)
	}
	if n := minter.mintCallCount(); n != 1 {
		t.Fatalf("mint should have run once (cap blocks the second before minting), got %d", n)
	}
}

func TestAuthenticateUpstream_RejectsDowngrades(t *testing.T) {
	cases := []struct {
		name string
		send func(be *pgproto3.Backend)
	}{
		{"md5", func(be *pgproto3.Backend) { be.Send(&pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}}) }},
		{"gss", func(be *pgproto3.Backend) { be.Send(&pgproto3.AuthenticationGSS{}) }},
		{"cleartext-insecure", func(be *pgproto3.Backend) { be.Send(&pgproto3.AuthenticationCleartextPassword{}) }},
		{"sasl-no-scram", func(be *pgproto3.Backend) {
			be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = serverConn.Close() }()
			go func() {
				be := pgproto3.NewBackend(serverConn, serverConn)
				tc.send(be)
				_ = be.Flush()
			}()
			fe := pgproto3.NewFrontend(clientConn, clientConn)
			if err := authenticateUpstream(fe, &Lease{Password: "vault-pw"}, false); err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestReadStartup_DeclinesSSLThenReadsStartup(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	go func() {
		// Client: SSLRequest, expect 'N', then a real StartupMessage.
		_, _ = clientConn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
		buf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, buf); err != nil || buf[0] != 'N' {
			return
		}
		fe := pgproto3.NewFrontend(clientConn, clientConn)
		fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent"}})
		_ = fe.Flush()
	}()
	be := pgproto3.NewBackend(serverConn, serverConn)
	startup, err := readStartup(be, serverConn)
	if err != nil {
		t.Fatalf("readStartup after SSL decline: %v", err)
	}
	if startup.Parameters["user"] != "agent" {
		t.Fatalf("unexpected startup params: %+v", startup.Parameters)
	}
}

func TestReadStartup_CancelRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	go func() {
		// CancelRequest: length 16, code 80877102, pid, secret.
		_, _ = clientConn.Write([]byte{0x00, 0x00, 0x00, 0x10, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 1, 0, 0, 0, 2})
	}()
	be := pgproto3.NewBackend(serverConn, serverConn)
	if _, err := readStartup(be, serverConn); err == nil {
		t.Fatal("expected CancelRequest to be surfaced as an error")
	}
}

func TestBroker_ClientErrorCodes(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	svc := &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}

	// Auth failure -> 28000, no mint.
	authMinter := &fakeMinter{lease: newLease()}
	_, authAddr := startBroker(t, Options{Auth: &fakeAuth{err: fmt.Errorf("bad token")}, Databases: &fakeResolver{svc: svc}, Leases: authMinter})
	if code := connectExpectCode(t, authAddr, "tok", "appdb"); code != "28000" {
		t.Errorf("auth failure code = %q, want 28000", code)
	}
	if authMinter.mintCallCount() != 0 {
		t.Errorf("mint must not run on auth failure")
	}

	// Resolve failure -> 3D000, no mint.
	resolveMinter := &fakeMinter{lease: newLease()}
	_, resolveAddr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}}, Databases: &fakeResolver{err: fmt.Errorf("no service")}, Leases: resolveMinter})
	if code := connectExpectCode(t, resolveAddr, "tok", "appdb"); code != "3D000" {
		t.Errorf("resolve failure code = %q, want 3D000", code)
	}
	if resolveMinter.mintCallCount() != 0 {
		t.Errorf("mint must not run on resolve failure")
	}

	// Mint failure -> 08006, no revoke.
	mintMinter := &fakeMinter{mintErr: fmt.Errorf("vault down")}
	_, mintAddr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}}, Databases: &fakeResolver{svc: svc}, Leases: mintMinter})
	if code := connectExpectCode(t, mintAddr, "tok", "appdb"); code != "08006" {
		t.Errorf("mint failure code = %q, want 08006", code)
	}
	if len(mintMinter.revokedLeases()) != 0 {
		t.Errorf("nothing minted, nothing to revoke")
	}
}

func TestBroker_DropsNonAllowlistedParamAndOverridesDatabase(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, "")
	upstream.forbidParam = "options" // must never be forwarded upstream
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Database: "override_db", Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:    minter,
	})

	// Send a non-allowlisted startup param ("options") via a hand-built startup.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{
		"user": "agent", "database": "requested_db", "options": "-c statement_timeout=0",
	}})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Complete auth + one query so the upstream records what it saw.
	sess := &agentSession{conn: conn, fe: fe}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("auth: %v", err)
		}
		if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); ok {
			fe.Send(&pgproto3.PasswordMessage{Password: "tok"})
			_ = fe.Flush()
			continue
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			t.Fatalf("startup error %s", er.Code)
		}
	}
	_, _ = sess.query("SELECT 1")

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.forbidSeen {
		t.Error("non-allowlisted param 'options' was forwarded to the upstream")
	}
	if upstream.lastDB != "override_db" {
		t.Errorf("service Database override not applied: upstream saw db %q, want override_db", upstream.lastDB)
	}
}

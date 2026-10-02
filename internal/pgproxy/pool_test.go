package pgproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakePeerAuth admits by peer address: each address is its own workload of one
// pool agent, as pool attestation does.
type fakePeerAuth struct {
	mu       sync.Mutex
	peers    []netip.Addr
	renewals int
	notAfter time.Time
}

func (f *fakePeerAuth) Authenticate(context.Context, string, string) (*AgentScope, error) {
	return nil, fmt.Errorf("token-only path must not be used for pool workers")
}

func (f *fakePeerAuth) AuthenticatePeer(_ context.Context, _, _ string, peer netip.Addr, renewal bool) (*AgentScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = append(f.peers, peer)
	if renewal {
		f.renewals++
	}
	return &AgentScope{VaultID: "vault", ActorID: "pool-agent", WorkloadID: "pod-" + peer.String(), NotAfter: f.notAfter}, nil
}

func (f *fakePeerAuth) seen() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.peers...)
}

// openSession completes the agent handshake after an optional PROXY header and
// leaves the session open.
func openSession(t *testing.T, addr, header string) (net.Conn, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if header != "" {
		if _, err := conn.Write([]byte(header)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "appdb"}})
	if err := fe.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			conn.Close()
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: "projected-token"})
			if err := fe.Flush(); err != nil {
				conn.Close()
				return nil, err
			}
		case *pgproto3.ErrorResponse:
			conn.Close()
			return nil, fmt.Errorf("%s (%s)", m.Message, m.Code)
		case *pgproto3.ReadyForQuery:
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}
	}
}

func poolBroker(t *testing.T, auth AgentAuthenticator, maxPerWorkload int) string {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	_, addr := startBroker(t, Options{
		Auth:                  auth,
		Databases:             &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:                &fakeMinter{lease: lease},
		TrustProxyHeader:      true,
		MaxLeasesPerActor:     maxPerWorkload,
		AuthorizationInterval: 50 * time.Millisecond,
	})
	return addr
}

func header(ip string) string { return "PROXY TCP4 " + ip + " 10.244.0.5 40000 15432\r\n" }

func TestPoolPeerComesFromTheProxyHeader(t *testing.T) {
	auth := &fakePeerAuth{}
	addr := poolBroker(t, auth, 4)
	conn, err := openSession(t, addr, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	for _, peer := range auth.seen() {
		if peer != netip.MustParseAddr("10.244.0.9") {
			t.Fatalf("authenticated peer %v, want the PROXY source", peer)
		}
	}
	if len(auth.seen()) < 2 {
		t.Fatal("admission and its recheck were not both bound to the peer")
	}
}

func TestPoolConnectionWithoutProxyHeaderIsRefused(t *testing.T) {
	auth := &fakePeerAuth{}
	addr := poolBroker(t, auth, 4)
	if conn, err := openSession(t, addr, ""); err == nil {
		conn.Close()
		t.Fatal("a connection without the terminator's PROXY header was admitted")
	}
	if len(auth.seen()) != 0 {
		t.Fatal("authentication ran without a trusted peer")
	}
}

func TestPoolCapIsPerWorkloadNotPerAgent(t *testing.T) {
	auth := &fakePeerAuth{}
	addr := poolBroker(t, auth, 1)
	held, err := openSession(t, addr, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if conn, err := openSession(t, addr, header("10.244.0.9")); err == nil {
		conn.Close()
		t.Fatal("a worker exceeded its own cap")
	}
	other, err := openSession(t, addr, header("10.244.0.10"))
	if err != nil {
		t.Fatalf("one worker at its cap blocked another worker of the same pool: %v", err)
	}
	other.Close()
}

func TestPoolSessionEndsAtThePodDeadline(t *testing.T) {
	auth := &fakePeerAuth{notAfter: time.Now().Add(400 * time.Millisecond)}
	addr := poolBroker(t, auth, 4)
	conn, err := openSession(t, addr, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the broker to close the session at the deadline")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("session outlived the Pod deadline")
	}
}

func TestPoolRecheckUsesRenewal(t *testing.T) {
	auth := &fakePeerAuth{}
	addr := poolBroker(t, auth, 4)
	conn, err := openSession(t, addr, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, 2*time.Second, func() bool { auth.mu.Lock(); defer auth.mu.Unlock(); return auth.renewals > 0 }, "no renewal recheck")
}

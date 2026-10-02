package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
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

// spoofedConn reports a chosen remote address, as a connection arriving from
// off the Pod would, while carrying bytes over a real socket.
type spoofedConn struct {
	net.Conn
	remote net.Addr
}

func (c spoofedConn) RemoteAddr() net.Addr { return c.remote }

func handleWithRemote(t *testing.T, b *Broker, remote net.Addr, header string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(header))
		fe := pgproto3.NewFrontend(c, c)
		fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "appdb"}})
		_ = fe.Flush()
		if _, ok := mustReceive(fe).(*pgproto3.AuthenticationCleartextPassword); ok {
			fe.Send(&pgproto3.PasswordMessage{Password: "projected-token"})
			_ = fe.Flush()
			_ = mustReceive(fe)
		}
	}()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); b.handleConn(spoofedConn{Conn: server, remote: remote}, func() {}) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not finish")
	}
}

func mustReceive(fe *pgproto3.Frontend) pgproto3.BackendMessage {
	msg, err := fe.Receive()
	if err != nil {
		return nil
	}
	return msg
}

func TestForgedProxyHeaderFromNonLoopbackPeerIsRefused(t *testing.T) {
	newBroker := func(auth AgentAuthenticator) *Broker {
		lease := newLease()
		return New("127.0.0.1:0", Options{Auth: auth, Databases: &fakeResolver{svc: &DatabaseService{Name: "a", Addr: "127.0.0.1:1"}},
			Leases: &fakeMinter{lease: lease}, TrustProxyHeader: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	}
	forged := header("10.244.0.9")
	auth := &fakePeerAuth{}
	handleWithRemote(t, newBroker(auth), &net.TCPAddr{IP: net.IPv4(10, 244, 0, 66), Port: 40000}, forged)
	if len(auth.seen()) != 0 {
		t.Fatal("a PROXY header from a non-loopback connection reached authentication")
	}
	// Positive control: the same header from the loopback terminator is parsed.
	control := &fakePeerAuth{}
	handleWithRemote(t, newBroker(control), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, forged)
	if seen := control.seen(); len(seen) == 0 || seen[0] != netip.MustParseAddr("10.244.0.9") {
		t.Fatalf("loopback terminator's header not used: %v", seen)
	}
}

func TestProxyHeaderRequiresLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- the test proves this listener is refused
	if err != nil {
		t.Skip("cannot bind a non-loopback listener here")
	}
	b := New(ln.Addr().String(), Options{Auth: &fakePeerAuth{}, Databases: &fakeResolver{}, Leases: &fakeMinter{}, TrustProxyHeader: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := b.Serve(ln); err == nil {
		t.Fatal("a PROXY-reading broker served on a non-loopback listener")
	}
	loop, _ := net.Listen("tcp", "127.0.0.1:0")
	control := New(loop.Addr().String(), Options{Auth: &fakePeerAuth{}, Databases: &fakeResolver{}, Leases: &fakeMinter{}, TrustProxyHeader: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	served := make(chan error, 1)
	go func() { served <- control.Serve(loop) }()
	time.Sleep(100 * time.Millisecond)
	_ = control.Shutdown(context.Background())
	if err := <-served; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("loopback listener refused: %v", err)
	}
}

// fakeLedger stands in for the shared store: one count per workload across
// every broker that uses it.
type fakeLedger struct {
	mu       sync.Mutex
	sessions map[string]string
	err      error
}

func (l *fakeLedger) Add(_ context.Context, id, workload string, limit int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	n := 0
	for _, w := range l.sessions {
		if w == workload {
			n++
		}
	}
	if limit > 0 && n >= limit {
		return ErrSessionLimit
	}
	l.sessions[id] = workload
	return nil
}

func (l *fakeLedger) Remove(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, id)
	return nil
}

func fleetBroker(t *testing.T, ledger SessionLedger, cap int) string {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	_, addr := startBroker(t, Options{Auth: &fakePeerAuth{}, Sessions: ledger, TrustProxyHeader: true, MaxLeasesPerActor: cap,
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    &fakeMinter{lease: lease}, AuthorizationInterval: time.Second})
	return addr
}

func TestPodCapHoldsAcrossBrokerReplicas(t *testing.T) {
	ledger := &fakeLedger{sessions: map[string]string{}}
	first, second := fleetBroker(t, ledger, 1), fleetBroker(t, ledger, 1)
	held, err := openSession(t, first, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := openSession(t, second, header("10.244.0.9")); err == nil {
		conn.Close()
		t.Fatal("a second replica let the same Pod past its cap")
	} else if !strings.Contains(err.Error(), "53300") {
		t.Fatalf("refusal was not the capacity error: %v", err)
	}
	other, err := openSession(t, second, header("10.244.0.10"))
	if err != nil {
		t.Fatalf("another Pod was blocked: %v", err)
	}
	other.Close()
	held.Close()
	waitFor(t, 2*time.Second, func() bool { ledger.mu.Lock(); defer ledger.mu.Unlock(); return len(ledger.sessions) == 0 }, "ended sessions were not removed from the ledger")
}

func TestLedgerOutageRefusesSessions(t *testing.T) {
	ledger := &fakeLedger{sessions: map[string]string{}, err: errors.New("store down")}
	if conn, err := openSession(t, fleetBroker(t, ledger, 4), header("10.244.0.9")); err == nil {
		conn.Close()
		t.Fatal("a session was admitted without the shared count")
	}
}

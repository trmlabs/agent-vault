package mitm

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

type fakeAttestor struct {
	mu       sync.Mutex
	peers    []netip.Addr
	tokens   []string
	notAfter time.Time
	err      error
}

func (a *fakeAttestor) Attest(_ context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers, a.tokens = append(a.peers, peer), append(a.tokens, token)
	if a.err != nil {
		return nil, a.err
	}
	return &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", NotAfter: a.notAfter}, nil
}

func (a *fakeAttestor) seen() []netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]netip.Addr(nil), a.peers...)
}

// readTestProxyV1 parses "PROXY TCP4 <src> <dst> <sport> <dport>\r\n" one byte
// at a time, so nothing after the header is consumed.
func readTestProxyV1(c net.Conn) (netip.Addr, error) {
	var line []byte
	b := make([]byte, 1)
	for len(line) < 108 {
		if _, err := c.Read(b); err != nil {
			return netip.Addr{}, err
		}
		line = append(line, b[0])
		if strings.HasSuffix(string(line), "\r\n") {
			fields := strings.Fields(string(line))
			if len(fields) != 6 || fields[0] != "PROXY" {
				return netip.Addr{}, errors.New("malformed")
			}
			return netip.ParseAddr(fields[2])
		}
	}
	return netip.Addr{}, errors.New("header too long")
}

// attestedFixture is the adapter fixture with an Attestor in front and a
// token-review resolver that must never be consulted.
func attestedFixture(t *testing.T, attestor *fakeAttestor, reader PeerReader, header string) *adapterFixture {
	t.Helper()
	f := newAdapterFixture(t, func(o *Options) {
		o.Attestor, o.PeerReader = attestor, reader
		o.Sessions = &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
			t.Error("token review consulted while an Attestor is configured")
			return nil, brokercore.ErrInvalidSession
		}}
	})
	if header != "" {
		transport := f.client.Transport.(*http.Transport)
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err == nil {
				_, err = io.WriteString(c, header)
			}
			return c, err
		}
	}
	return f
}

func TestAttestorAdmitsByTokenAndConnectionPeer(t *testing.T) {
	attestor := &fakeAttestor{}
	f := attestedFixture(t, attestor, nil, "")
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", nil); err != nil || code != 200 {
		t.Fatalf("attested call: %d %v", code, err)
	}
	peers := attestor.seen()
	if len(peers) < 2 || peers[0] != netip.MustParseAddr("127.0.0.1") || attestor.tokens[0] != "workload-token" {
		t.Fatalf("attestor saw %v", peers)
	}
	if e := f.audit.last(); e.PodUID != "pod-uid-1" || e.Pool != "pool-agent" {
		t.Fatalf("scope not from the attestor: %+v", e)
	}
}

// Behind a loopback TLS terminator, the peer comes from its PROXY header.
func TestAttestorUsesProxyHeaderPeer(t *testing.T) {
	attestor := &fakeAttestor{}
	f := attestedFixture(t, attestor, readTestProxyV1, "PROXY TCP4 10.20.30.40 10.0.0.1 51000 14443\r\n")
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err != nil || code != 200 {
		t.Fatalf("call behind terminator: %d %v", code, err)
	}
	for _, peer := range attestor.seen() {
		if peer != netip.MustParseAddr("10.20.30.40") {
			t.Fatalf("attestor saw %v", peer)
		}
	}
}

func TestAttestorRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attestor *fakeAttestor
		reader   PeerReader
		header   string
	}{
		{"malformed PROXY header", &fakeAttestor{}, readTestProxyV1, "GARBAGE\r\n"},
		{"missing PROXY header", &fakeAttestor{}, readTestProxyV1, ""},
		{"attestation denied", &fakeAttestor{err: errors.New("pod not running")}, nil, ""},
		{"past deadline", &fakeAttestor{notAfter: time.Now().Add(-time.Second)}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := attestedFixture(t, tc.attestor, tc.reader, tc.header)
			if tc.name == "missing PROXY header" {
				f.client.Timeout = 8 * time.Second
			}
			code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil)
			if err == nil && code == 200 || f.calls.Load() != 0 {
				t.Fatalf("admitted: %d %v calls=%d", code, err, f.calls.Load())
			}
			if strings.Contains(tc.name, "PROXY") && len(tc.attestor.seen()) != 0 {
				t.Fatal("attestor called without a peer")
			}
		})
	}
}

// A tunnel, even one still streaming, ends at the Pod's deadline.
func TestTunnelEndsAtScopeDeadline(t *testing.T) {
	attestor := &fakeAttestor{notAfter: time.Now().Add(700 * time.Millisecond)}
	f := attestedFixture(t, attestor, nil, "")
	defer close(f.release)
	r, _ := http.NewRequest("GET", f.url("/v1/stream"), nil)
	r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	if first, err := reader.ReadString('\n'); err != nil || first != "data: first\n" {
		t.Fatalf("first event: %q %v", first, err)
	}
	started := time.Now()
	_, err = io.ReadAll(reader)
	if err == nil {
		t.Fatal("stream completed past the deadline")
	}
	if waited := time.Since(started); waited > 3*time.Second {
		t.Fatalf("tunnel outlived the deadline by %v", waited)
	}
}

// spoofedListener makes every accepted connection report a remote, non-loopback
// peer, as a client reaching the listener from outside the Pod would.
type spoofedListener struct{ net.Listener }

type spoofedConn struct{ net.Conn }

func (spoofedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.9.8.7"), Port: 40000}
}

func (l spoofedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return spoofedConn{c}, nil
}

// A client outside the broker Pod sends a forged PROXY header claiming a
// worker's address. The header is never parsed, the Attestor is never asked,
// and the connection is refused. The same bytes from a loopback peer are
// parsed and attested, so the test can tell the two apart.
func TestForgedProxyHeaderFromNonLoopbackPeerIsRefused(t *testing.T) {
	send := func(t *testing.T, spoof bool) (bool, []netip.Addr, string) {
		attestor := &fakeAttestor{err: errors.New("stop after attestation")}
		var parsed atomic.Bool
		reader := func(c net.Conn) (netip.Addr, error) { parsed.Store(true); return readTestProxyV1(c) }
		p := New("127.0.0.1:0", Options{Logger: slog.New(slog.DiscardHandler), Attestor: attestor, PeerReader: reader,
			StrictCredentialProxy: true, DurableAudit: &faultAudit{sink: requestlog.NewDurable(nil)},
			Sessions: &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
				t.Error("token review consulted")
				return nil, brokercore.ErrInvalidSession
			}}})
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := net.Listener(l)
		if spoof {
			accepted = spoofedListener{l}
		}
		go func() { _ = p.httpServer.Serve(peerListener{Listener: accepted, reader: p.peerReader}) }()
		t.Cleanup(func() { _ = p.httpServer.Close() })
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, "PROXY TCP4 10.20.30.40 10.0.0.1 51000 14443\r\nCONNECT example.com:443 HTTP/1.1\r\n"+
			"Host: example.com:443\r\nConnection: close\r\nProxy-Authorization: Basic d29ya2xvYWQtdG9rZW46\r\n\r\n")
		response, _ := io.ReadAll(c)
		return parsed.Load(), attestor.seen(), string(response)
	}
	parsed, attested, response := send(t, true)
	if parsed || len(attested) != 0 || strings.Contains(response, " 200 ") {
		t.Fatalf("forged header honored: parsed=%v attested=%v response=%q", parsed, attested, response)
	}
	parsed, attested, _ = send(t, false)
	if !parsed || len(attested) != 1 || attested[0] != netip.MustParseAddr("10.20.30.40") {
		t.Fatalf("control: loopback header not used: parsed=%v attested=%v", parsed, attested)
	}
}

// The broker refuses to serve PROXY-header peers on any listener not bound to
// loopback, so the header can only ever come from inside the Pod.
func TestProxyHeaderRequiresLoopbackListener(t *testing.T) {
	p := New("0.0.0.0:0", Options{Attestor: &fakeAttestor{}, PeerReader: readTestProxyV1})
	l, err := net.Listen("tcp", "0.0.0.0:0") //nolint:gosec // G102: the test needs a non-loopback listener to prove it is refused
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Serve(l); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback listener served PROXY peers: %v", err)
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("listener left open")
	}
}

// reattestingAttestor refuses Attest once its token has "expired" but keeps
// passing Reattest, like the real pool attestor for a tunnel older than its token.
type reattestingAttestor struct {
	fakeAttestor
	mu        sync.Mutex
	expired   bool
	reattests int
}

func (a *reattestingAttestor) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	expired := a.expired
	a.mu.Unlock()
	if expired {
		return nil, errors.New("token expired")
	}
	return a.fakeAttestor.Attest(ctx, token, peer)
}

func (a *reattestingAttestor) Reattest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	a.reattests++
	a.mu.Unlock()
	return a.fakeAttestor.Attest(ctx, token, peer)
}

// A tunnel opened with a valid token keeps working after the token expires:
// requests inside it are rechecked with Reattest, which keeps the Pod checks.
func TestTunnelRechecksUseReattest(t *testing.T) {
	attestor := &reattestingAttestor{}
	f := newAdapterFixture(t, func(o *Options) { o.Attestor = attestor })
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", nil); err != nil || code != 200 {
		t.Fatalf("first request: %d %v", code, err)
	}
	attestor.mu.Lock()
	attestor.expired = true
	attestor.mu.Unlock()
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", nil); err != nil || code != 200 {
		t.Fatalf("request in the open tunnel after token expiry: %d %v", code, err)
	}
	attestor.mu.Lock()
	defer attestor.mu.Unlock()
	if attestor.reattests < 2 {
		t.Fatalf("in-tunnel requests used Reattest %d times", attestor.reattests)
	}
}

// Reading the PROXY header restores the HTTP server's read deadline instead
// of clearing it, so a client behind the terminator cannot hold a connection
// open forever before authenticating.
func TestProxyHeaderKeepsTheServerReadDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	accepted, err := (peerListener{Listener: l, reader: readTestProxyV1}).Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = accepted.Close() }()
	if _, err := client.Write([]byte("PROXY TCP4 10.0.0.9 10.0.0.1 40000 14443\r\n")); err != nil {
		t.Fatal(err)
	}
	// As net/http does: a header deadline, then the first read.
	_ = accepted.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		_, err := accepted.Read(make([]byte, 64))
		done <- err
	}()
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("read after the PROXY header: %v, want the server's deadline to expire", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the PROXY header read cleared the server's read deadline")
	}
	if peer, err := accepted.(*peerConn).Peer(); err != nil || peer.String() != "10.0.0.9" {
		t.Fatalf("peer %v %v", peer, err)
	}
}

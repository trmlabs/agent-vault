package mitm

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
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
	return &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", WorkloadID: "pod-uid-1", NotAfter: a.notAfter}, nil
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

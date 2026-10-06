package mitm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type kindAttestor struct{ kind string }

func (a kindAttestor) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	return &brokercore.ProxyScope{AgentID: "agent", VaultID: "vault", IdentityKind: a.kind}, nil
}

// Each listener admits only the identity kinds it was opened for.
func TestListenerAdmitsOnlyItsIdentityKinds(t *testing.T) {
	cross := []string{brokercore.KindProxyAttested}
	peer := netip.MustParseAddr("10.200.0.7")
	for name, c := range map[string]struct {
		kind  string
		kinds []string
		ok    bool
	}{
		"pool Pod on a pool listener":            {brokercore.KindPodToken, nil, true},
		"proxy on a pool listener":               {brokercore.KindProxyAttested, nil, false},
		"proxy on the cross-cluster listener":    {brokercore.KindProxyAttested, cross, true},
		"pool Pod on the cross-cluster listener": {brokercore.KindPodToken, cross, false},
		// A Claude session's Pod proves itself with its own token too; the
		// runner session only names the person.
		"session-jwt caller on the cross-cluster listener": {brokercore.KindPodToken, cross, false},
		"token review on the cross-cluster listener":       {brokercore.KindTokenReview, cross, false},
		"legacy session on the cross-cluster":              {"", cross, false},
	} {
		a, b := net.Pipe()
		conn := net.Conn(a)
		if c.kinds != nil {
			conn = &brokercore.KindedConn{Conn: a, Kinds: c.kinds}
		}
		ctx := withSessionToken(withPeerConn(context.Background(), &peerConn{Conn: conn}), "runner.session.token")
		p := &Proxy{attestor: kindAttestor{c.kind}}
		_, err := p.resolveScope(ctx, "token", "", peer, nil, false)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

// testListenerWrap, when set, wraps the test proxy's listener.
var testListenerWrap func(net.Listener) net.Listener

type crossClusterListener struct{ net.Listener }

func (l crossClusterListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &brokercore.KindedConn{Conn: c, Kinds: []string{brokercore.KindProxyAttested}}, nil
}

// A proxy-attested CONNECT on the cross-cluster listener carries its
// listener's kinds into the tunnel: the requests inside it are served, and
// the same proxy on a pool listener is refused at the CONNECT.
func TestCrossClusterTunnelServesItsRequests(t *testing.T) {
	for name, cross := range map[string]bool{"cross-cluster listener": true, "pool listener": false} {
		if cross {
			testListenerWrap = func(l net.Listener) net.Listener { return crossClusterListener{l} }
		}
		f := newAdapterFixture(t, func(o *Options) {
			o.Attestor = kindAttestorScope{&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent",
				WorkloadID: "agent-pod-uid", VaultRole: "proxy", IdentityKind: brokercore.KindProxyAttested}}
		})
		testListenerWrap = nil
		code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", nil)
		if cross && (err != nil || code != 200) {
			t.Errorf("%s: %d %v", name, code, err)
		}
		if !cross && err == nil && code == 200 {
			t.Errorf("%s: a proxy-attested tunnel was served", name)
		}
	}
}

type kindAttestorScope struct{ scope *brokercore.ProxyScope }

func (a kindAttestorScope) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	s := *a.scope
	return &s, nil
}

// Refusals are logged by reason code, at most once per reason per interval,
// with the count of those folded in.
func TestRefusalLogIsRateLimitedByReason(t *testing.T) {
	var buf bytes.Buffer
	p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	for i := 0; i < 5; i++ {
		p.logRefusal("proxy_source", nil)
	}
	p.logRefusal("catalog_profile", nil)
	out := buf.String()
	if strings.Count(out, "reason=proxy_source") != 1 || strings.Count(out, "reason=catalog_profile") != 1 {
		t.Fatalf("log: %s", out)
	}
	p.refusals.last["proxy_source"] = time.Now().Add(-refusalLogEvery)
	p.logRefusal("proxy_source", nil)
	if !strings.Contains(buf.String(), "reason=proxy_source count=5") {
		t.Fatalf("folded count missing: %s", buf.String())
	}
}

// A signing-key refusal's line and audit row name the token's kid and the
// connection's peer. A kid that is not a plain identifier is
// chosen by whoever made the token, so it is recorded as "invalid" plus a hash
// prefix, and its row is still written: the caller gets 403, not 503.
func TestKeyRefusalNamesKidAndPeer(t *testing.T) {
	peer := netip.MustParseAddr("10.20.30.40")
	for _, c := range []struct {
		name, reason, kid, wantKid string
		hashed                     bool
	}{
		{"pinned", "token_keys_pinned_mismatch", "ZQVpb7vyW0cXKr--ggHnuB24sV1iYirOsQNSZKxruVI", "ZQVpb7vyW0cXKr--ggHnuB24sV1iYirOsQNSZKxruVI", false},
		{"in-cluster", "token_keys_in_cluster_unknown", "k.1_a", "k.1_a", false},
		{"signature", "token_signature", "k1", "k1", false},
		{"quote", "token_signature", `k"1`, "invalid", true},
		{"space", "token_keys_pinned_mismatch", "k 1", "invalid", true},
		{"long", "token_keys_unavailable", strings.Repeat("k", 600), "invalid", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal := brokercore.WithPeer(brokercore.DeniedKey(c.reason, c.kid), peer)
			sum := sha256.Sum256([]byte(c.kid))
			wantHash := ""
			if c.hashed {
				wantHash = hex.EncodeToString(sum[:])[:12]
			}
			var buf bytes.Buffer
			p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
			p.logRefusal(brokercore.DenialReason(refusal), brokercore.DenialKey(refusal))
			line := buf.String()
			want := "reason=" + c.reason + " count=1 kid=" + c.wantKid
			if c.hashed {
				want += " kid_sha256=" + wantHash
			}
			if !strings.Contains(line, want+" peer=10.20.30.40") || (c.hashed && strings.Contains(line, c.kid)) {
				t.Fatalf("log line %q", line)
			}
			var proxyLog bytes.Buffer
			attestor := &tokenRecordingAttestor{err: refusal}
			f := newAdapterFixture(t, func(o *Options) {
				o.Attestor, o.Logger = attestor, slog.New(slog.NewTextHandler(&proxyLog, nil))
			})
			// A token shaped like a real one: header, payload, signature.
			f.client = newTrustingClient(f.proxyURL, url.User(fakeJWT), f.roots)
			// The tunnel is refused at CONNECT: 403, never 503 for a row the
			// chain would not take.
			_, _, err := f.do(t, "GET", "/v1/chat/x", "", nil)
			if err == nil || !strings.HasSuffix(err.Error(), ": Forbidden") || strings.Contains(err.Error(), c.reason) {
				t.Fatalf("caller saw %v", err)
			}
			e := f.audit.last()
			if e.Event != "denied" || e.Decision != "identity_"+c.reason || e.Kid != c.wantKid || e.KidSHA256 != wantHash || e.Peer != "10.20.30.40" || e.Status != 403 {
				t.Fatalf("audit row %+v", e)
			}
			// The token reached the attestor, and no part of it reached the
			// proxy's log or the row.
			token := attestor.token()
			if token != fakeJWT {
				t.Fatalf("the attestor saw %q", token)
			}
			for _, part := range strings.Split(token, ".") {
				if strings.Contains(proxyLog.String(), part) || strings.Contains(fmt.Sprintf("%+v", f.audit.all()), part) {
					t.Fatalf("token part %q in log %q or rows", part, proxyLog.String())
				}
			}
			if !strings.Contains(proxyLog.String(), want+" peer=10.20.30.40") || (c.hashed && strings.Contains(proxyLog.String(), c.kid)) {
				t.Fatalf("proxy log %q", proxyLog.String())
			}
		})
	}
	// Refusals that are not at the signing key keep their plain line.
	var buf bytes.Buffer
	p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	p.logRefusal("proxy_source", brokercore.DenialKey(brokercore.WithPeer(brokercore.Denied("proxy_source"), peer)))
	if strings.Contains(buf.String(), "kid=") || strings.Contains(buf.String(), "peer=") {
		t.Fatalf("plain refusal line %q", buf.String())
	}
}

type refusingAttestor struct{ err error }

// fakeJWT has a real token's three segments; none may reach a log or row.
const fakeJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6eDp5In0.c2lnbmF0dXJlLWJ5dGVz"

// tokenRecordingAttestor refuses, keeping the token it was shown.
type tokenRecordingAttestor struct {
	err  error
	mu   sync.Mutex
	seen string
}

func (a *tokenRecordingAttestor) Attest(_ context.Context, token string, _ netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = token
	return nil, a.err
}

func (a *tokenRecordingAttestor) token() string { a.mu.Lock(); defer a.mu.Unlock(); return a.seen }

func (a refusingAttestor) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	return nil, a.err
}

// A refused identity's audit row names the check that refused it; the
// caller still gets a bare 403.
func TestIdentityRefusalIsAuditedWithItsReason(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) { o.Attestor = refusingAttestor{brokercore.Denied("proxy_source")} })
	code, body, _ := f.do(t, "GET", "/v1/chat/x", "", nil)
	if code == 200 || strings.Contains(body, "proxy_source") {
		t.Fatalf("caller saw %d %q", code, body)
	}
	if e := f.audit.last(); e.Event != "denied" || e.Decision != "identity_proxy_source" || e.Status != 403 {
		t.Fatalf("audit row %+v", e)
	}
	// A refusal without a code keeps the plain row.
	g := newAdapterFixture(t, func(o *Options) { o.Attestor = refusingAttestor{brokercore.ErrInvalidSession} })
	g.do(t, "GET", "/v1/chat/x", "", nil)
	if e := g.audit.last(); e.Event != "denied" || e.Decision != "" {
		t.Fatalf("plain refusal row %+v", e)
	}
}

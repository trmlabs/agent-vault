package mitm

import (
	"context"
	"net"
	"net/netip"
	"testing"

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

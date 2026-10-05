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
		"legacy session on the cross-cluster":    {"", cross, false},
	} {
		a, b := net.Pipe()
		conn := net.Conn(a)
		if c.kinds != nil {
			conn = &brokercore.KindedConn{Conn: a, Kinds: c.kinds}
		}
		ctx := withPeerConn(context.Background(), &peerConn{Conn: conn})
		p := &Proxy{attestor: kindAttestor{c.kind}}
		_, err := p.resolveScope(ctx, "token", "", peer, nil, false)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

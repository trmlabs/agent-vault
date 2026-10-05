package pgproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// kindedListener tags every connection with the identity kinds it admits,
// as the cross-cluster dispatcher does.
type kindedListener struct {
	net.Listener
	kinds []string
}

func (l kindedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &brokercore.KindedConn{Conn: c, Kinds: l.kinds}, nil
}

func kindBroker(t *testing.T, kind string, kinds []string) string {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	auth := &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-7", IdentityKind: kind}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := net.Listener(ln)
	if kinds != nil {
		l = kindedListener{Listener: ln, kinds: kinds}
	}
	b := New(ln.Addr().String(), Options{Auth: auth, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    &fakeMinter{lease: lease}})
	go func() { _ = b.Serve(l) }()
	t.Cleanup(func() { _ = b.Shutdown(context.Background()) })
	return ln.Addr().String()
}

// Each listener admits only the identity kinds it was opened for.
func TestListenerAdmitsOnlyItsIdentityKinds(t *testing.T) {
	cross := []string{brokercore.KindProxyAttested}
	for name, c := range map[string]struct {
		kind  string
		kinds []string
		ok    bool
	}{
		"pool Pod on a pool listener":                {brokercore.KindPodToken, nil, true},
		"legacy session on a pool listener":          {"", nil, true},
		"proxy on a pool listener":                   {brokercore.KindProxyAttested, nil, false},
		"proxy on the cross-cluster listener":        {brokercore.KindProxyAttested, cross, true},
		"pool Pod on the cross-cluster listener":     {brokercore.KindPodToken, cross, false},
		"token review on the cross-cluster listener": {brokercore.KindTokenReview, cross, false},
	} {
		addr := kindBroker(t, c.kind, c.kinds)
		_, err := runAgentQuery(t, addr, "agent-vault-token-xyz", "appdb", "SELECT current_user")
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

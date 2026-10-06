package mitm

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// recordingAttestor admits everything and records the attestation each
// admission and recheck saw.
type recordingAttestor struct {
	fakeAttestor
	mu   sync.Mutex
	seen []string
}

func (a *recordingAttestor) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	a.seen = append(a.seen, brokercore.AttestationFrom(ctx))
	a.mu.Unlock()
	return a.fakeAttestor.Attest(ctx, token, peer)
}

// A shared proxy's CONNECT attestation reaches the admission and every
// per-request recheck; a request inside the tunnel cannot replace it.
func TestConnectAttestationReachesEveryCheck(t *testing.T) {
	attestor := &recordingAttestor{}
	f := newAdapterFixture(t, func(o *Options) {
		o.Attestor = attestor
		o.Sessions = &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
			t.Error("token review consulted while an Attestor is configured")
			return nil, brokercore.ErrInvalidSession
		}}
	})
	f.client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{brokercore.AttestationHeader: {"attested-by-proxy"}}
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", func(r *http.Request) {
		r.Header.Set(brokercore.AttestationHeader, "forged-inside-tunnel")
	}); err != nil || code != 200 {
		t.Fatalf("call: %d %v", code, err)
	}
	attestor.mu.Lock()
	defer attestor.mu.Unlock()
	if len(attestor.seen) < 2 {
		t.Fatalf("checks %v", attestor.seen)
	}
	for _, got := range attestor.seen {
		if got != "attested-by-proxy" {
			t.Fatalf("check saw %q", got)
		}
	}
}

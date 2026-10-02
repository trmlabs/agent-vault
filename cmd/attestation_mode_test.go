package cmd

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type attestingResolver struct{}

func (attestingResolver) ResolveForProxy(context.Context, string, string) (*brokercore.ProxyScope, error) {
	return nil, nil
}
func (attestingResolver) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	return nil, nil
}

func TestTokenReviewModeHidesAttest(t *testing.T) {
	var full brokercore.SessionResolver = attestingResolver{}
	if _, ok := full.(brokercore.Attestor); !ok {
		t.Fatal("positive control: resolver should attest")
	}
	var hidden brokercore.SessionResolver = tokenReviewOnly{full}
	if _, ok := hidden.(brokercore.Attestor); ok {
		t.Fatal("tokenreview mode still exposes Attest")
	}
}

package mitm

import "testing"

// The tunnel bound defaults to fleet scale and follows an explicit setting.
func TestTunnelLimitDefaultsToFleetScale(t *testing.T) {
	if p := New("127.0.0.1:0", Options{}); cap(p.strictTunnels) != DefaultMaxTunnels || DefaultMaxTunnels < 10000 {
		t.Fatalf("default tunnel limit %d", cap(p.strictTunnels))
	}
	if p := New("127.0.0.1:0", Options{MaxCredentialProxyTunnels: 50000}); cap(p.strictTunnels) != 50000 {
		t.Fatalf("explicit tunnel limit %d", cap(p.strictTunnels))
	}
}

package mitm

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// Behind a shared proxy every sandbox has the proxy's address: on the
// proxy-attested listener the auth-failure budget is per attested sandbox,
// and on any other listener a header changes nothing.
func TestAuthFailureKeyIsPerAttestedSandbox(t *testing.T) {
	attest := func(owner string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"ownerUID":"` + owner + `"}`))
	}
	request := func(kinds []string, owner string) string {
		r := httptest.NewRequest("CONNECT", "http://api.example.com:443", nil)
		r.RemoteAddr = "10.65.0.50:40000"
		if owner != "" {
			r.Header.Set(brokercore.AttestationHeader, attest(owner))
		}
		return mitmIPKey(r.WithContext(withKinds(r.Context(), kinds)))
	}
	proxy := []string{brokercore.KindProxyAttested}
	a, b := request(proxy, "sandbox-a"), request(proxy, "sandbox-b")
	if a == b || a != "mitm:10.65.0.50/sandbox:sandbox-a" {
		t.Fatalf("keys %q %q", a, b)
	}
	if got := request(proxy, ""); got != "mitm:10.65.0.50" {
		t.Fatalf("no attestation: %q", got)
	}
	direct := []string{brokercore.KindPodToken, brokercore.KindProxyAttested}
	if got := request(direct, "sandbox-a"); got != "mitm:10.65.0.50" {
		t.Fatalf("a header on a mixed listener changed the key: %q", got)
	}
}

func TestProxyLimitIsPerPod(t *testing.T) {
	pool := func(pod string) string {
		return proxyLimitActor(&brokercore.ProxyScope{AgentID: "pool-agent", WorkloadID: pod})
	}
	if pool("pod-a") == pool("pod-b") {
		t.Fatal("two Pods of one pool share a budget")
	}
	if got := proxyLimitActor(&brokercore.ProxyScope{AgentID: "legacy"}); got != "legacy" {
		t.Fatalf("legacy session key %q", got)
	}
}

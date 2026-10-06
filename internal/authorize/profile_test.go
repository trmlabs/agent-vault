package authorize

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// profiledPools parses today's Cursor and Claude pools twice: once with no
// harnesses (profiles derived from the pool) and once with explicit harness
// entries, so each decision can be compared between the two.
func profiledPools(t *testing.T) (derived, explicit httpcatalog.Catalog) {
	t.Helper()
	pools := `"pools":[{"name":"cursor","namespace":"cursor","serviceAccount":"worker"},
		{"name":"ci","namespace":"ci","serviceAccount":"runner","identity":"workload"},
		{"name":"claude","namespace":"claude","serviceAccount":"session","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
		"entries":[{"name":"vendor","host":"api.vendor.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["cursor","ci","claude"]}]`
	domain := `"trustDomain":{"issuer":"https://kubernetes.default.svc.cluster.local","keys":"in-cluster","audience":"gatehouse"}`
	harnesses := `"harnesses":[
		{"name":"cursor",` + domain + `,"identity":{"kind":"pod-token","ownerKind":"ReplicaSet","namespaces":["cursor"],"imageDigests":["` + digest + `"]},"path":{"kind":"sidecar"},"authorization":{"mode":"pool","poolName":"cursor"},"client":{"proxyEnv":"GATEHOUSE_HTTPS_PROXY","caFileEnv":"GATEHOUSE_CA_FILE"}},
		{"name":"ci",` + domain + `,"identity":{"kind":"pod-token","ownerKind":"Job","namespaces":["ci"],"imageDigests":["` + digest + `"]},"path":{"kind":"sidecar"},"authorization":{"mode":"pool","poolName":"ci"},"client":{"proxyEnv":"HTTPS_PROXY","caFileEnv":"SSL_CERT_FILE"}},
		{"name":"claude",` + domain + `,"identity":{"kind":"session-jwt","ownerKind":"Job","namespaces":["claude"],"imageDigests":["` + digest + `"]},"path":{"kind":"sidecar"},"authorization":{"mode":"person","poolName":"claude"},"client":{"proxyEnv":"HTTPS_PROXY","caFileEnv":"SSL_CERT_FILE"}}],`
	var err error
	if derived, err = httpcatalog.Parse([]byte(`{` + pools + `}`)); err != nil {
		t.Fatal(err)
	}
	if explicit, err = httpcatalog.Parse([]byte(`{` + harnesses + pools + `}`)); err != nil {
		t.Fatal(err)
	}
	return derived, explicit
}

// Re-expressing Cursor and Claude as harness entries changes no decision.
func TestExplicitProfilesDecideAsDerivedOnes(t *testing.T) {
	derived, explicit := profiledPools(t)
	ctx := context.Background()
	cases := []struct{ pool, session, pod string }{
		{"cursor", "", "pod-a"},
		{"cursor", "alice", "pod-a"}, // session_unexpected
		{"ci", "", "pod-a"},
		{"ci", "alice", "pod-a"},
		{"claude", "", "pod-a"},
		{"claude", "alice", "pod-a"},
		{"claude", "alice", ""},        // session_unbindable
		{"claude", "mallory", "pod-a"}, // session_token
	}
	for _, c := range cases {
		dp, _ := derived.Pool(c.pool)
		ep, _ := explicit.Pool(c.pool)
		if dp.Profile().Explicit || !ep.Profile().Explicit {
			t.Fatalf("%s: profiles not as built", c.pool)
		}
		dWho, dRefusal := Resolve(ctx, dp, c.session, c.pod, oneToken{}, &authorizetest.MemBinder{})
		eWho, eRefusal := Resolve(ctx, ep, c.session, c.pod, oneToken{}, &authorizetest.MemBinder{})
		if dWho != eWho || dRefusal != eRefusal {
			t.Errorf("%+v: derived %+v %q, explicit %+v %q", c, dWho, dRefusal, eWho, eRefusal)
		}
	}
	// The pinned pair: the explicit Claude profile still pins a session to
	// its first Pod.
	ep, _ := explicit.Pool("claude")
	b := &authorizetest.MemBinder{}
	if _, refusal := Resolve(ctx, ep, "alice", "pod-a", oneToken{}, b); refusal != "" {
		t.Fatalf("first Pod: %q", refusal)
	}
	if _, refusal := Resolve(ctx, ep, "alice", "pod-b", oneToken{}, b); refusal != "session_pod_mismatch" {
		t.Fatalf("second Pod: %q", refusal)
	}
}

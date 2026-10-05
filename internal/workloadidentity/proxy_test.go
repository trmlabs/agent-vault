package workloadidentity

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// The private link's source range, and an address inside it.
var linkIP = netip.MustParseAddr("10.200.0.7")

type proxyFixture struct {
	pool *poolFixture
	rc   *remoteCluster
	r    *Resolver
	a    Attestation
}

func setupProxy(t *testing.T) *proxyFixture {
	t.Helper()
	f := setupPool(t)
	rc := newRemoteCluster(t)
	c := f.r.config
	c.TrustDomains = []TrustDomain{rc.td}
	c.Bindings = append(append([]Binding(nil), c.Bindings...), Binding{
		Namespace: "gatehouse-edge", ServiceAccount: "gatehouse-edge", ServiceAccountUID: "edge-account-uid",
		AgentID: "agent", VaultID: "vault", Pool: "sandboxes", TrustDomain: "agent-sandbox",
		Proxy: &ProxyBinding{Namespaces: []string{"agent-sandboxes"}, OwnerKind: "Sandbox", ImageDigests: []string{workerDigest},
			SourceCIDRs: []string{"10.200.0.0/24"}, MaxSessionSeconds: 3600},
	})
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	return &proxyFixture{pool: f, rc: rc, r: r, a: Attestation{Namespace: "agent-sandboxes", PodName: "sandbox-x1", PodUID: "agent-pod-uid",
		OwnerKind: "Sandbox", OwnerUID: "sandbox-uid", ImageDigests: []string{workerDigest}, NotAfter: time.Now().Add(30 * time.Minute).Unix()}}
}

func (p *proxyFixture) ctx(t *testing.T, a Attestation) context.Context {
	t.Helper()
	encoded, err := EncodeAttestation(a)
	if err != nil {
		t.Fatal(err)
	}
	return brokercore.WithAttestation(context.Background(), encoded)
}

func TestProxyAttestedAdmitsTheAttestedPod(t *testing.T) {
	p := setupProxy(t)
	scope, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(p.rc.claims()), linkIP)
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadID != "agent-pod-uid" || scope.Pool != "sandboxes" || scope.AgentID != "agent" || !scope.NotAfter.Equal(time.Unix(p.a.NotAfter, 0)) {
		t.Fatalf("scope %+v", scope)
	}
	// A recheck after the proxy token expired still holds until the agent's
	// deadline, within the session cap.
	c := p.rc.claims()
	c.Issued = time.Now().Unix() - 700
	c.Expires = c.Issued + 600
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if _, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(c), linkIP); err == nil {
		t.Fatal("new connection on an expired proxy token")
	}
	// The cap counts from the proxy token's issue time.
	c.Issued = time.Now().Unix() - 3601
	c.Expires = c.Issued + 600
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err == nil {
		t.Fatal("session outlived its cap")
	}
}

// Every error path denies.
func TestProxyAttestedRefusals(t *testing.T) {
	type input struct {
		ctx   context.Context
		token string
		peer  netip.Addr
	}
	cases := map[string]func(t *testing.T, p *proxyFixture) input{
		"no attestation": func(t *testing.T, p *proxyFixture) input {
			return input{context.Background(), p.rc.token(p.rc.claims()), linkIP}
		},
		"malformed attestation": func(t *testing.T, p *proxyFixture) input {
			return input{brokercore.WithAttestation(context.Background(), "not-base64!"), p.rc.token(p.rc.claims()), linkIP}
		},
		"source outside the private link": func(t *testing.T, p *proxyFixture) input {
			return input{p.ctx(t, p.a), p.rc.token(p.rc.claims()), netip.MustParseAddr("10.201.0.7")}
		},
		"wrong-issuer proxy token": func(t *testing.T, p *proxyFixture) input {
			c := p.rc.claims()
			c.Issuer = "https://container.googleapis.com/v1/projects/other/locations/l/clusters/c"
			return input{p.ctx(t, p.a), p.rc.token(c), linkIP}
		},
		"forged proxy token": func(t *testing.T, p *proxyFixture) input {
			return input{p.ctx(t, p.a), p.pool.tokenWithKid(p.rc.claims(), p.rc.kid), linkIP}
		},
		"wrong proxy account UID": func(t *testing.T, p *proxyFixture) input {
			c := p.rc.claims()
			c.Kubernetes.ServiceAccount.UID = "recreated-account-uid"
			return input{p.ctx(t, p.a), p.rc.token(c), linkIP}
		},
		"another account in the proxy namespace": func(t *testing.T, p *proxyFixture) input {
			c := p.rc.claims()
			c.Subject, c.Kubernetes.ServiceAccount.Name = "system:serviceaccount:gatehouse-edge:default", "default"
			return input{p.ctx(t, p.a), p.rc.token(c), linkIP}
		},
		"wrong audience": func(t *testing.T, p *proxyFixture) input {
			c := p.rc.claims()
			c.Audience = []string{"gatehouse"}
			return input{p.ctx(t, p.a), p.rc.token(c), linkIP}
		},
		"Pod not owned by a Sandbox": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.OwnerKind = "ReplicaSet"
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"namespace not listed": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.Namespace = "kube-system"
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"image digest mismatch": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.ImageDigests = []string{workerDigest, otherDigest}
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"agent past its deadline": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.NotAfter = time.Now().Add(-time.Second).Unix()
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"no owner UID": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.OwnerUID = ""
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"own pool worker presenting an attestation": func(t *testing.T, p *proxyFixture) input {
			return input{p.ctx(t, p.a), p.pool.token(p.pool.c), workerIP}
		},
	}
	for name, build := range cases {
		p := setupProxy(t)
		in := build(t, p)
		if scope, err := p.r.Attest(in.ctx, in.token, in.peer); err == nil {
			t.Errorf("%s: admitted %+v", name, scope)
		}
	}
	// The token-only path never admits a proxy binding.
	p := setupProxy(t)
	if _, err := p.r.ResolveForProxy(p.ctx(t, p.a), p.rc.token(p.rc.claims()), ""); err == nil {
		t.Error("ResolveForProxy admitted a proxy binding")
	}
}

// The declared profile is checked at every admission, for pool Pods and
// proxies alike.
func TestAdmissionMatchesTheDeclaredProfile(t *testing.T) {
	p := setupProxy(t)
	ownIssuer := p.pool.c.Issuer
	profiles := map[string]Profile{
		"database-developers": {Issuer: ownIssuer, Audience: "gatehouse", Kind: IdentityPodToken, OwnerKind: "ReplicaSet",
			Namespaces: []string{"pool"}, ImageDigests: []string{workerDigest, sidecarDigest}},
		"sandboxes": {Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested, OwnerKind: "Sandbox",
			Namespaces: []string{"agent-sandboxes"}, ImageDigests: []string{workerDigest}},
	}
	p.r.SetProfiles(func(pool string) (Profile, bool) { pr, ok := profiles[pool]; return pr, ok })
	p.pool.pod["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["kind"] = "ReplicaSet"
	admit := func() (error, error) {
		_, poolErr := p.r.Attest(context.Background(), p.pool.token(p.pool.c), workerIP)
		_, proxyErr := p.r.Attest(p.ctx(t, p.a), p.rc.token(p.rc.claims()), linkIP)
		return poolErr, proxyErr
	}
	if poolErr, proxyErr := admit(); poolErr != nil || proxyErr != nil {
		t.Fatalf("matching profiles: pool %v, proxy %v", poolErr, proxyErr)
	}
	for name, change := range map[string]func(){
		"pool: another owner kind": func() {
			pr := profiles["database-developers"]
			pr.OwnerKind = "Job"
			profiles["database-developers"] = pr
		},
		"pool: image not listed": func() {
			pr := profiles["database-developers"]
			pr.ImageDigests = []string{workerDigest}
			profiles["database-developers"] = pr
		},
		"pool: profile is a proxy": func() {
			pr := profiles["database-developers"]
			pr.Kind = IdentityProxyAttested
			profiles["database-developers"] = pr
		},
		"pool: another issuer": func() {
			pr := profiles["database-developers"]
			pr.Issuer = remoteIssuer
			profiles["database-developers"] = pr
		},
		"proxy: namespace narrowed": func() { pr := profiles["sandboxes"]; pr.Namespaces = []string{"other"}; profiles["sandboxes"] = pr },
		"proxy: in-cluster keys":    func() { pr := profiles["sandboxes"]; pr.Remote = false; profiles["sandboxes"] = pr },
		"proxy: profile is a pod":   func() { pr := profiles["sandboxes"]; pr.Kind = IdentityPodToken; profiles["sandboxes"] = pr },
	} {
		saved := map[string]Profile{"database-developers": profiles["database-developers"], "sandboxes": profiles["sandboxes"]}
		change()
		poolErr, proxyErr := admit()
		if poolErr == nil && proxyErr == nil {
			t.Errorf("%s: both admitted", name)
		}
		profiles["database-developers"], profiles["sandboxes"] = saved["database-developers"], saved["sandboxes"]
	}
}

func TestProxyBindingValidation(t *testing.T) {
	for name, mutate := range map[string]func(b *Binding){
		"no namespaces":         func(b *Binding) { b.Proxy.Namespaces = nil },
		"no owner kind":         func(b *Binding) { b.Proxy.OwnerKind = "" },
		"no image digests":      func(b *Binding) { b.Proxy.ImageDigests = nil },
		"no source range":       func(b *Binding) { b.Proxy.SourceCIDRs = nil },
		"any source":            func(b *Binding) { b.Proxy.SourceCIDRs = []string{"0.0.0.0/0"} },
		"unmasked source":       func(b *Binding) { b.Proxy.SourceCIDRs = []string{"10.200.0.7/24"} },
		"no session cap":        func(b *Binding) { b.Proxy.MaxSessionSeconds = 0 },
		"no pool":               func(b *Binding) { b.Pool = "" },
		"with owner UIDs":       func(b *Binding) { b.OwnerUIDs = []string{"x"} },
		"with a Pod UID":        func(b *Binding) { b.PodUID = "x" },
		"with own image digest": func(b *Binding) { b.ImageDigests = []string{workerDigest} },
	} {
		p := setupProxy(t)
		c := p.r.config
		c.Bindings = append([]Binding(nil), c.Bindings...)
		proxy := *c.Bindings[1].Proxy
		c.Bindings[1].Proxy = &proxy
		mutate(&c.Bindings[1])
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

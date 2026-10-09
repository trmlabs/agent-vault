package workloadidentity

import (
	"context"
	"errors"
	"fmt"
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
		AgentID: "agent", VaultID: "vault", TrustDomain: "agent-sandbox",
		Proxy: &ProxyBinding{Profiles: []ProxyProfile{
			{Namespace: "agent-sandboxes", Profile: "agent-sandbox-developers", Pool: "sandboxes"},
			{Namespace: "orion-sandboxes", Profile: "agent-sandbox-orion", Pool: "orion"}},
			OwnerKind: "Sandbox", ImageDigests: []string{workerDigest}, SourceCIDRs: []string{"10.200.0.0/24"}, MaxSessionSeconds: 1800},
	})
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	// The catalog's profiles: one per namespace, from the sandbox cluster.
	r.SetProfiles(func(pool string) (Profile, bool) {
		profile := Profile{Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested, OwnerKind: "Sandbox",
			ImageDigests: []string{workerDigest}}
		switch pool {
		case "sandboxes":
			profile.Name, profile.Namespaces = "agent-sandbox-developers", []string{"agent-sandboxes"}
		case "orion":
			profile.Name, profile.Namespaces = "agent-sandbox-orion", []string{"orion-sandboxes"}
		default:
			return Profile{}, false
		}
		return profile, true
	})
	return &proxyFixture{pool: f, rc: rc, r: r, a: Attestation{Namespace: "agent-sandboxes", PodName: "sandbox-x1", PodUID: "agent-pod-uid",
		OwnerKind: "Sandbox", OwnerUID: "sandbox-uid", Images: []string{"registry.example/worker@" + workerDigest}, NotAfter: time.Now().Add(20 * time.Minute).Unix(),
		Profile: "agent-sandbox-developers"}}
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
	if scope.AttestedRequester != "" {
		t.Fatalf("a requester the proxy did not attest: %q", scope.AttestedRequester)
	}
	// The attested requester reaches the scope as is; authorization decides
	// whether the pool's profile takes one.
	withRequester := p.a
	withRequester.Requester = "alice.smith@example.com"
	if scope, err := p.r.Attest(p.ctx(t, withRequester), p.rc.token(p.rc.claims()), linkIP); err != nil || scope.AttestedRequester != "alice.smith@example.com" {
		t.Fatalf("requester not carried: %+v %v", scope, err)
	}
	// A recheck after the proxy token expired still holds, but only for one
	// token lifetime (3600 s in this domain) past its expiry.
	c := p.rc.claims()
	c.Issued = time.Now().Unix() - 700
	c.Expires = c.Issued + 600
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if _, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(c), linkIP); err == nil {
		t.Fatal("new connection on an expired proxy token")
	}
	// The session cap (1800 s) counts from the proxy token's issue time.
	c.Issued = time.Now().Unix() - 1801
	c.Expires = c.Issued + 600
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err == nil {
		t.Fatal("session outlived its cap")
	}
}

// A proxy token from a 600-second domain holds a recheck at most 600 s past
// its expiry, even inside the session cap.
func TestExpiredProxyTokenRecheckIsBounded(t *testing.T) {
	p := setupProxy(t)
	p.r.domains[1].maxLifetime = 600
	c := p.rc.claims()
	c.Issued = time.Now().Unix() - 1100
	c.Expires = c.Issued + 600 // expired 500 s ago
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err != nil {
		t.Fatalf("recheck inside the bound: %v", err)
	}
	c.Issued = time.Now().Unix() - 1300
	c.Expires = c.Issued + 600 // expired 700 s ago
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(c), linkIP); err == nil {
		t.Fatal("recheck 700 s past a 600 s token's expiry admitted")
	}
}

// The namespace picks the profile and pool: customer sandboxes land in their
// external pool, developer sandboxes in theirs, anything else is refused.
func TestNamespacePicksTheProfile(t *testing.T) {
	p := setupProxy(t)
	token := p.rc.token(p.rc.claims())
	developers, err := p.r.Attest(p.ctx(t, p.a), token, linkIP)
	if err != nil || developers.Pool != "sandboxes" {
		t.Fatalf("developers: %v %+v", err, developers)
	}
	orion := p.a
	orion.Namespace, orion.Profile = "orion-sandboxes", "agent-sandbox-orion"
	if scope, err := p.r.Attest(p.ctx(t, orion), token, linkIP); err != nil || scope.Pool != "orion" {
		t.Fatalf("orion: %v %+v", err, scope)
	}
	for name, mutate := range map[string]func(a *Attestation){
		"unknown namespace":               func(a *Attestation) { a.Namespace = "other-sandboxes" },
		"another namespace's profile":     func(a *Attestation) { a.Profile = "agent-sandbox-orion" },
		"orion namespace, developer pool": func(a *Attestation) { a.Namespace = "orion-sandboxes" },
		"no profile":                      func(a *Attestation) { a.Profile = "" },
	} {
		a := p.a
		mutate(&a)
		if scope, err := p.r.Attest(p.ctx(t, a), token, linkIP); err == nil {
			t.Errorf("%s: admitted %+v", name, scope)
		}
	}
	// A catalog profile from another trust domain, or none, admits nothing.
	p.r.SetProfiles(func(string) (Profile, bool) {
		return Profile{Name: "agent-sandbox-developers", Issuer: p.pool.c.Issuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested,
			OwnerKind: "Sandbox", Namespaces: []string{"agent-sandboxes"}, ImageDigests: []string{workerDigest}}, true
	})
	if _, err := p.r.Attest(p.ctx(t, p.a), token, linkIP); err == nil {
		t.Error("admitted under a profile of another trust domain")
	}
	p.r.SetProfiles(func(string) (Profile, bool) { return Profile{}, false })
	if _, err := p.r.Attest(p.ctx(t, p.a), token, linkIP); err == nil {
		t.Error("admitted with no catalog profile")
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
		"namespace not listed, with its claimed profile": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.Namespace, a.Profile = "kube-system", "kube-system"
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"namespace not listed": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.Namespace = "kube-system"
			return input{p.ctx(t, a), p.rc.token(p.rc.claims()), linkIP}
		},
		"image digest mismatch": func(t *testing.T, p *proxyFixture) input {
			a := p.a
			a.Images = []string{"registry.example/worker@" + workerDigest, "registry.example/other@" + otherDigest}
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
		"sandboxes": {Name: "agent-sandbox-developers", Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested, OwnerKind: "Sandbox",
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
		"no profiles": func(b *Binding) { b.Proxy.Profiles = nil },
		"repeated namespace": func(b *Binding) {
			b.Proxy.Profiles = append(b.Proxy.Profiles, ProxyProfile{Namespace: "agent-sandboxes", Profile: "x", Pool: "y"})
		},
		"profile with no pool":     func(b *Binding) { b.Proxy.Profiles = []ProxyProfile{{Namespace: "n", Profile: "p"}} },
		"own pool":                 func(b *Binding) { b.Pool = "sandboxes" },
		"session over the ceiling": func(b *Binding) { b.Proxy.MaxSessionSeconds = 24*3600 + 1 },
		"no owner kind":            func(b *Binding) { b.Proxy.OwnerKind = "" },
		"no image digests":         func(b *Binding) { b.Proxy.ImageDigests = nil },
		"no source range":          func(b *Binding) { b.Proxy.SourceCIDRs = nil },
		"any source":               func(b *Binding) { b.Proxy.SourceCIDRs = []string{"0.0.0.0/0"} },
		"unmasked source":          func(b *Binding) { b.Proxy.SourceCIDRs = []string{"10.200.0.7/24"} },
		"session under a minute":   func(b *Binding) { b.Proxy.MaxSessionSeconds = 59 },
		"with owner UIDs":          func(b *Binding) { b.OwnerUIDs = []string{"x"} },
		"with a Pod UID":           func(b *Binding) { b.PodUID = "x" },
		"with own image digest":    func(b *Binding) { b.ImageDigests = []string{workerDigest} },
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

// Within one trust domain, a namespace belongs to one proxy binding.
func TestNamespaceInTwoProxyBindingsIsRefused(t *testing.T) {
	p := setupProxy(t)
	c := p.r.config
	second := c.Bindings[1]
	second.ServiceAccount, second.ServiceAccountUID = "gatehouse-edge-2", "edge-2-uid"
	proxy := *second.Proxy
	proxy.Profiles = []ProxyProfile{{Namespace: "agent-sandboxes", Profile: "other", Pool: "other"}}
	second.Proxy = &proxy
	c.Bindings = append(append([]Binding(nil), c.Bindings...), second)
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
		t.Fatal("one namespace served by two proxies was accepted")
	}
	proxy.Profiles = []ProxyProfile{{Namespace: "third-sandboxes", Profile: "third", Pool: "third"}}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("a second proxy for another namespace refused: %v", err)
	}
}

// Item 8, exactly: a recheck holds until the proxy token's expiry plus the
// domain's lifetime (at most 1200 s from issue at 600 s), a new session needs
// an unexpired token, and no session outlives 1800 s from issue.
func TestProxyRecheckLimits(t *testing.T) {
	p := setupProxy(t)
	p.r.domains[1].maxLifetime = 600
	now := time.Now()
	p.r.now = func() time.Time { return now }
	at := func(issuedAgo int64) claims {
		c := p.rc.claims()
		c.Issued = now.Unix() - issuedAgo
		c.Expires = c.Issued + 600
		return c
	}
	// (a) expired 599 s ago: one second inside exp + 600.
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(at(1199)), linkIP); err != nil {
		t.Fatalf("(a) recheck at the limit minus 1 s refused: %v", err)
	}
	// (b) expired 601 s ago: one second past exp + 600.
	if _, err := p.r.Reattest(p.ctx(t, p.a), p.rc.token(at(1201)), linkIP); err == nil {
		t.Fatal("(b) recheck at the limit plus 1 s admitted")
	}
	// (c) a new session never takes an expired token.
	if _, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(at(601)), linkIP); err == nil {
		t.Fatal("(c) new session on an expired token admitted")
	}
	// (d) the 1800 s cap ends a session, whatever the recheck bound allows.
	p.r.domains[1].maxLifetime = 3600
	a := p.a
	a.NotAfter = now.Add(time.Hour).Unix()
	scope, err := p.r.Reattest(p.ctx(t, a), p.rc.token(at(1799)), linkIP)
	if err != nil || !scope.NotAfter.Equal(time.Unix(now.Unix()-1799+1800, 0)) {
		t.Fatalf("(d) session 1 s before its cap: %v %+v", err, scope)
	}
	if _, err := p.r.Reattest(p.ctx(t, a), p.rc.token(at(1800)), linkIP); err == nil {
		t.Fatal("(d) session at 1800 s not ended")
	}
}

const (
	orionPrefix     = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/"
	developerPrefix = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/"
)

// With image prefixes, each namespace runs what its tenant path pulled, and
// the platform's own containers run listed digests.
func TestProxyImagePrefixes(t *testing.T) {
	p := setupProxy(t)
	c := p.r.config
	c.Bindings = append([]Binding(nil), c.Bindings...)
	proxy := *c.Bindings[1].Proxy
	proxy.Profiles = []ProxyProfile{
		{Namespace: "agent-sandboxes", Profile: "agent-sandbox-developers", Pool: "sandboxes", ImagePrefix: developerPrefix},
		{Namespace: "orion-sandboxes", Profile: "agent-sandbox-orion", Pool: "orion", ImagePrefix: orionPrefix}}
	proxy.ImageDigests = []string{sidecarDigest} // a platform sidecar
	c.Bindings[1].Proxy = &proxy
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	r.SetProfiles(func(pool string) (Profile, bool) {
		profile := Profile{Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested, OwnerKind: "Sandbox",
			ImageDigests: []string{sidecarDigest}}
		switch pool {
		case "sandboxes":
			profile.Name, profile.Namespaces, profile.ImagePrefix = "agent-sandbox-developers", []string{"agent-sandboxes"}, developerPrefix
		case "orion":
			profile.Name, profile.Namespaces, profile.ImagePrefix = "agent-sandbox-orion", []string{"orion-sandboxes"}, orionPrefix
		default:
			return Profile{}, false
		}
		return profile, true
	})
	token := p.rc.token(p.rc.claims())
	orion := p.a
	orion.Namespace, orion.Profile = "orion-sandboxes", "agent-sandbox-orion"
	for name, c := range map[string]struct {
		a      Attestation
		images []string
		ok     bool
	}{
		"orion agent with the platform sidecar": {orion, []string{orionPrefix + "agent@" + workerDigest, "registry.example/gcsfuse@" + sidecarDigest}, true},
		"developer agent":                       {p.a, []string{developerPrefix + "team/tool@" + otherDigest}, true},
		"the proxy image as an agent":           {orion, []string{"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/gatehouse/proxy@" + workerDigest}, false},
		"a developer image in orion":            {orion, []string{developerPrefix + "tool@" + otherDigest}, false},
		"an orion image in developers":          {p.a, []string{orionPrefix + "agent@" + workerDigest}, false},
		"an unlisted platform image":            {orion, []string{orionPrefix + "agent@" + workerDigest, "registry.example/other@" + otherDigest}, false},
		"a tag, not a pull":                     {orion, []string{orionPrefix + "agent:latest"}, false},
	} {
		a := c.a
		a.Images = c.images
		if _, err := r.Attest(p.ctx(t, a), token, linkIP); (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// The catalog profile must name the binding's prefix.
	r.SetProfiles(func(pool string) (Profile, bool) {
		return Profile{Name: "agent-sandbox-orion", Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested,
			OwnerKind: "Sandbox", Namespaces: []string{"orion-sandboxes"}, ImagePrefix: developerPrefix, ImageDigests: []string{sidecarDigest}}, true
	})
	orion.Images = []string{orionPrefix + "agent@" + workerDigest}
	if _, err := r.Attest(p.ctx(t, orion), token, linkIP); err == nil {
		t.Error("admitted under a catalog profile with another prefix")
	}
	for name, mutate := range map[string]func(b *ProxyBinding){
		"overlapping prefixes": func(b *ProxyBinding) {
			b.Profiles[1].ImagePrefix = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/"
		},
		"another project":       func(b *ProxyBinding) { b.Profiles[1].ImagePrefix = "us-central1-docker.pkg.dev/other/repo/orion/" },
		"no prefix, no digests": func(b *ProxyBinding) { b.Profiles[1].ImagePrefix, b.ImageDigests = "", nil },
	} {
		cc := c
		cc.Bindings = append([]Binding(nil), c.Bindings...)
		bad := proxy
		bad.Profiles = append([]ProxyProfile(nil), proxy.Profiles...)
		mutate(&bad)
		cc.Bindings[1].Proxy = &bad
		if _, err := New(cc, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Each refusal names the check that refused it, as a fixed code, and is
// still ErrInvalidSession to every caller.
func TestRefusalsNameTheirCheck(t *testing.T) {
	p := setupProxy(t)
	token := p.rc.token(p.rc.claims())
	unknown := p.a
	unknown.Namespace = "other-sandboxes"
	wrongProfile := p.a
	wrongProfile.Profile = "agent-sandbox-orion"
	for want, call := range map[string]func() error{
		"proxy_source": func() error {
			_, err := p.r.Attest(p.ctx(t, p.a), token, netip.MustParseAddr("10.201.0.7"))
			return err
		},
		"attestation_namespace": func() error { _, err := p.r.Attest(p.ctx(t, unknown), token, linkIP); return err },
		"attestation_profile":   func() error { _, err := p.r.Attest(p.ctx(t, wrongProfile), token, linkIP); return err },
		"catalog_profile": func() error {
			p.r.SetProfiles(func(string) (Profile, bool) { return Profile{}, false })
			defer setupProfiles(p)
			_, err := p.r.Attest(p.ctx(t, p.a), token, linkIP)
			return err
		},
		"token_issuer": func() error {
			c := p.rc.claims()
			c.Issuer = "https://unknown.example"
			_, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(c), linkIP)
			return err
		},
		"attestation_not_proxy": func() error {
			_, err := p.r.Attest(p.ctx(t, p.a), p.pool.token(p.pool.c), workerIP)
			return err
		},
	} {
		err := call()
		if brokercore.DenialReason(err) != want || !errors.Is(err, brokercore.ErrInvalidSession) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

// setupProfiles restores the fixture's catalog profiles.
func setupProfiles(p *proxyFixture) {
	p.r.SetProfiles(func(pool string) (Profile, bool) {
		profile := Profile{Issuer: remoteIssuer, Audience: "gatehouse-edge", Remote: true, Kind: IdentityProxyAttested, OwnerKind: "Sandbox",
			ImageDigests: []string{workerDigest}}
		switch pool {
		case "sandboxes":
			profile.Name, profile.Namespaces = "agent-sandbox-developers", []string{"agent-sandboxes"}
		case "orion":
			profile.Name, profile.Namespaces = "agent-sandbox-orion", []string{"orion-sandboxes"}
		default:
			return Profile{}, false
		}
		return profile, true
	})
}

// A shared proxy may serve 10,000 tenant namespaces, and its operator lists
// stay roomy; past those bounds the configuration is refused as malformed.
func TestProxyBindingListsAreFleetSized(t *testing.T) {
	load := func(mutate func(b *Binding)) error {
		p := setupProxy(t)
		c := p.r.config
		c.Bindings = append([]Binding(nil), c.Bindings...)
		proxy := *c.Bindings[1].Proxy
		c.Bindings[1].Proxy = &proxy
		mutate(&c.Bindings[1])
		_, err := New(c, &fakeStore{status: "active", role: "proxy"})
		return err
	}
	profiles := func(n int) func(b *Binding) {
		return func(b *Binding) {
			b.Proxy.Profiles = nil
			for i := range n {
				b.Proxy.Profiles = append(b.Proxy.Profiles, ProxyProfile{Namespace: fmt.Sprintf("tenant-%d", i), Profile: "agent-sandbox-developers", Pool: "sandboxes"})
			}
		}
	}
	ranges := func(n int) func(b *Binding) {
		return func(b *Binding) {
			b.Proxy.SourceCIDRs = nil
			for i := range n {
				b.Proxy.SourceCIDRs = append(b.Proxy.SourceCIDRs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
			}
		}
	}
	if err := load(profiles(10000)); err != nil {
		t.Fatalf("10,000 namespaces: %v", err)
	}
	if err := load(ranges(1024)); err != nil {
		t.Fatalf("1,024 source ranges: %v", err)
	}
	if load(profiles(10001)) == nil || load(ranges(1025)) == nil {
		t.Fatal("a list past its bound was accepted")
	}
}

// A shared proxy asking for its serving certificate is admitted as itself:
// its own current token, from its link's range. Nothing else qualifies.
func TestVerifyProxyAdmitsOnlyTheProxy(t *testing.T) {
	p := setupProxy(t)
	if err := p.r.VerifyProxy(context.Background(), p.rc.token(p.rc.claims()), linkIP); err != nil {
		t.Fatalf("the proxy was refused: %v", err)
	}
	expired := p.rc.claims()
	expired.Issued = time.Now().Unix() - 700
	expired.Expires = expired.Issued + 600
	for name, tc := range map[string]struct {
		token string
		peer  netip.Addr
	}{
		"outside the link's range": {p.rc.token(p.rc.claims()), netip.MustParseAddr("10.9.9.9")},
		"expired proxy token":      {p.rc.token(expired), linkIP},
		"a pool worker":            {p.pool.token(p.pool.c), linkIP},
		"loopback":                 {p.rc.token(p.rc.claims()), netip.MustParseAddr("127.0.0.1")},
		"no token":                 {"", linkIP},
	} {
		if err := p.r.VerifyProxy(context.Background(), tc.token, tc.peer); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

// A requester, when present, must be a lower-case login; the broker refuses
// any other value before it looks at the rest of the attestation.
func TestAttestationRequester(t *testing.T) {
	a := setupProxy(t).a
	for _, requester := range []string{"", "alice.smith@example.com", "a+b@sub.example.com"} {
		a.Requester = requester
		encoded, _ := EncodeAttestation(a)
		if got, err := decodeAttestation(encoded); err != nil || got.Requester != requester {
			t.Errorf("%q refused: %v", requester, err)
		}
	}
	for _, requester := range []string{"Alice@example.com", "alice", "alice@example", "@example.com", "alice@-example.com", "alice@example.com ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com"} {
		a.Requester = requester
		encoded, _ := EncodeAttestation(a)
		if _, err := decodeAttestation(encoded); err == nil {
			t.Errorf("%q accepted", requester)
		}
	}
}

// The session ceiling is one policy setting, a day by default: a proxy
// binding without its own cap takes it, and a pool binding's Pod lifetime and
// a proxy binding's cap may reach it but not pass it.
func TestSessionCeiling(t *testing.T) {
	p := setupProxy(t)
	if got := p.r.config.Bindings[1].Proxy.MaxSessionSeconds; got == 0 {
		t.Fatal("fixture has no proxy cap")
	}
	for name, tc := range map[string]struct {
		ceiling, pod, proxy int64
		ok                  bool
	}{
		"defaults":                {0, 24 * 3600, 0, true},
		"proxy takes the ceiling": {7200, 3600, 0, true},
		"pod past the ceiling":    {7200, 7201, 0, false},
		"proxy past the ceiling":  {7200, 3600, 7201, false},
		"week ceiling":            {7 * 24 * 3600, 7 * 24 * 3600, 7 * 24 * 3600, true},
		"ceiling past 30 days":    {30*24*3600 + 1, 3600, 3600, false},
		"ceiling under a minute":  {59, 3600, 3600, false},
	} {
		c := p.r.config
		c.MaxSessionSeconds = tc.ceiling
		c.Bindings = append([]Binding(nil), c.Bindings...)
		proxy := *c.Bindings[1].Proxy
		proxy.MaxSessionSeconds = tc.proxy
		c.Bindings[1].Proxy = &proxy
		for i := range c.Bindings {
			if c.Bindings[i].Proxy == nil && len(c.Bindings[i].OwnerUIDs) != 0 {
				c.Bindings[i].MaxPodSeconds = tc.pod
			}
		}
		r, err := New(c, &fakeStore{status: "active", role: "proxy"})
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err == nil && tc.proxy == 0 {
			want := tc.ceiling
			if want == 0 {
				want = 24 * 3600
			}
			if got := r.config.Bindings[1].Proxy.MaxSessionSeconds; got != want {
				t.Errorf("%s: proxy cap %d, want %d", name, got, want)
			}
		}
	}
}

package workloadidentity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const remoteIssuer = "https://container.googleapis.com/v1/projects/sandbox/locations/l/clusters/agent-sandbox"

// remoteCluster publishes another cluster's signing keys over HTTPS.
type remoteCluster struct {
	key   *rsa.PrivateKey
	kid   string
	td    TrustDomain
	calls atomic.Int64
	fail  atomic.Bool
}

func newRemoteCluster(t *testing.T) *remoteCluster {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rc := &remoteCluster{key: key, kid: "sandbox-key-1"}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.calls.Add(1)
		if r.URL.Path != "/jwks" || r.Header.Get("Authorization") != "" || rc.fail.Load() {
			w.WriteHeader(503)
			return
		}
		e := big.NewInt(int64(key.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": rc.kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "remote-ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
	rc.td = TrustDomain{Name: "agent-sandbox", Issuer: remoteIssuer, Audience: "gatehouse-edge", Keys: "remote", JWKSURL: srv.URL + "/jwks", CAFile: ca}
	return rc
}

// remoteClaims is a token the remote cluster issued to its proxy.
func (rc *remoteCluster) claims() claims {
	var c claims
	c.Issuer, c.Subject, c.Audience = remoteIssuer, "system:serviceaccount:gatehouse-edge:gatehouse-edge", []string{"gatehouse-edge"}
	c.Issued = time.Now().Unix() - 1
	c.Expires = c.Issued + 600
	c.Kubernetes.Namespace = "gatehouse-edge"
	c.Kubernetes.ServiceAccount.Name, c.Kubernetes.ServiceAccount.UID = "gatehouse-edge", "edge-account-uid"
	c.Kubernetes.Pod.Name, c.Kubernetes.Pod.UID = "gatehouse-edge-7d9", "edge-pod-uid"
	return c
}

func (rc *remoteCluster) token(c claims) string {
	f := &poolFixture{key: rc.key, kid: rc.kid}
	return f.token(c)
}

func withDomains(t *testing.T, f *poolFixture, domains ...TrustDomain) *Resolver {
	t.Helper()
	c := f.r.config
	c.TrustDomains = domains
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A token is verified against the keys of the domain that issued it, and
// each domain's keys are fetched and cached on their own.
func TestTrustDomainsVerifyByIssuer(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	r := withDomains(t, f, rc.td)
	ctx := context.Background()

	c, d, err := r.verifyLocally(ctx, rc.token(rc.claims()), false)
	if err != nil || d.name != "agent-sandbox" || !d.remote || c.Kubernetes.Pod.UID != "edge-pod-uid" {
		t.Fatalf("remote token: %v %+v", err, d)
	}
	if _, d, err := r.verifyLocally(ctx, f.token(f.c), false); err != nil || d.name != "" {
		t.Fatalf("own cluster token: %v %+v", err, d)
	}
	if rc.calls.Load() != 1 || f.jwksCalls.Load() != 1 {
		t.Fatalf("key fetches: remote %d, own %d", rc.calls.Load(), f.jwksCalls.Load())
	}
	// Cached: a second remote token fetches nothing.
	if _, _, err := r.verifyLocally(ctx, rc.token(rc.claims()), false); err != nil || rc.calls.Load() != 1 {
		t.Fatalf("cached: %v, fetches %d", err, rc.calls.Load())
	}
	// A failed refresh keeps the last good keys.
	rc.fail.Store(true)
	r.domains[1].keys.mu.Lock()
	r.domains[1].keys.fetched = time.Now().Add(-2 * jwksMaxAge)
	r.domains[1].keys.attempted = time.Now().Add(-2 * jwksRefetchBackoff)
	r.domains[1].keys.mu.Unlock()
	if _, _, err := r.verifyLocally(ctx, rc.token(rc.claims()), false); err != nil {
		t.Fatalf("last good keys dropped: %v", err)
	}
}

func TestTrustDomainRefusals(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	r := withDomains(t, f, rc.td)
	ctx := context.Background()
	cases := map[string]string{}
	{
		c := rc.claims()
		c.Issuer = "https://unknown.example"
		cases["unknown issuer"] = rc.token(c)
	}
	{
		// Signed by the broker's own cluster key, but claiming the remote issuer.
		cases["remote issuer, own cluster's key"] = f.tokenWithKid(rc.claims(), rc.kid)
	}
	{
		// Signed by the remote key, but claiming the broker's own issuer.
		cases["own issuer, remote key"] = rc.token(f.c)
	}
	{
		c := rc.claims()
		c.Audience = []string{"gatehouse"} // the own cluster's audience
		cases["another domain's audience"] = rc.token(c)
	}
	{
		c := rc.claims()
		c.Expires = c.Issued + 7200
		cases["lifetime over the domain's bound"] = rc.token(c)
	}
	{
		c := rc.claims()
		c.Expires = time.Now().Unix() - 1
		c.Issued = c.Expires - 600
		cases["expired"] = rc.token(c)
	}
	for name, token := range cases {
		if _, _, err := r.verifyLocally(ctx, token, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTrustDomainConfigRefusals(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	cases := map[string]func(c *Config){
		"plain HTTP keys":         func(c *Config) { c.TrustDomains[0].JWKSURL = "http://keys.example/jwks" },
		"no keys address":         func(c *Config) { c.TrustDomains[0].JWKSURL = "" },
		"in-cluster keys":         func(c *Config) { c.TrustDomains[0].Keys = "in-cluster" },
		"no audience":             func(c *Config) { c.TrustDomains[0].Audience = "" },
		"the broker's own issuer": func(c *Config) { c.TrustDomains[0].Issuer = c.Issuer },
		"repeated issuer": func(c *Config) {
			c.TrustDomains = append(c.TrustDomains, c.TrustDomains[0])
			c.TrustDomains[1].Name = "other"
		},
		"repeated name":     func(c *Config) { c.TrustDomains = append(c.TrustDomains, c.TrustDomains[0]) },
		"bad name":          func(c *Config) { c.TrustDomains[0].Name = "Agent Sandbox" },
		"lifetime too long": func(c *Config) { c.TrustDomains[0].MaxTokenLifetimeSeconds = 86400 },
		"unreadable CA":     func(c *Config) { c.TrustDomains[0].CAFile = "/nonexistent" },
		"binding names an unlisted domain": func(c *Config) {
			c.Bindings[0].TrustDomain = "elsewhere"
		},
		"pool binding in a remote domain": func(c *Config) {
			c.Bindings[0].TrustDomain = "agent-sandbox"
		},
	}
	for name, mutate := range cases {
		c := f.r.config
		c.Bindings = append([]Binding(nil), c.Bindings...)
		c.TrustDomains = []TrustDomain{rc.td}
		mutate(&c)
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The observer reads only its own cluster.
	c := f.r.config
	c.TrustDomains = []TrustDomain{rc.td}
	c.Bindings = []Binding{{Namespace: "observer", ServiceAccount: "observer", ServiceAccountUID: "observer-uid"}}
	if _, err := NewObserver(c); err == nil {
		t.Error("observer accepted trust domains")
	}
}

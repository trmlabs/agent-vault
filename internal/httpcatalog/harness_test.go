package httpcatalog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// harnessCatalog is the three harnesses Gatehouse serves: Cursor workers, Claude
// sessions and agent-sandbox, each with its pool and one entry granted to all.
func harnessCatalog() map[string]any {
	inCluster := map[string]any{"issuer": "https://container.googleapis.com/v1/projects/p/locations/l/clusters/us-saas", "keys": "in-cluster", "audience": "gatehouse"}
	return map[string]any{
		"harnesses": []any{
			map[string]any{"name": "cursor", "trustDomain": inCluster,
				"identity":      map[string]any{"kind": "pod-token", "ownerKind": "ReplicaSet", "namespaces": []any{"cursor"}, "imageDigests": []any{digestA, digestB}},
				"path":          map[string]any{"kind": "sidecar"},
				"authorization": map[string]any{"mode": "pool", "poolName": "cursor-workers"},
				"client":        map[string]any{"proxyEnv": "GATEHOUSE_HTTPS_PROXY", "caFileEnv": "GATEHOUSE_CA_FILE", "caSpkiEnv": "GATEHOUSE_CA_SPKI"}},
			map[string]any{"name": "claude", "trustDomain": inCluster,
				"identity":      map[string]any{"kind": "session-jwt", "ownerKind": "Job", "namespaces": []any{"claude"}, "imageDigests": []any{digestA}, "requester": map[string]any{"kind": "session-jwt"}},
				"path":          map[string]any{"kind": "sidecar"},
				"authorization": map[string]any{"mode": "person", "poolName": "claude-sessions"},
				"client":        map[string]any{"proxyEnv": "HTTPS_PROXY", "caFileEnv": "SSL_CERT_FILE", "caSpkiEnv": "GATEHOUSE_CA_SPKI"}},
			map[string]any{"name": "agent-sandbox", "trustDomain": map[string]any{"issuer": "https://container.googleapis.com/v1/projects/s/locations/l/clusters/sandbox", "keys": "remote", "audience": "gatehouse"},
				"identity":      map[string]any{"kind": "proxy-attested", "ownerKind": "Sandbox", "namespaces": []any{"agent-sandboxes"}, "imageDigests": []any{digestB}},
				"path":          map[string]any{"kind": "shared-proxy", "crossCluster": true},
				"authorization": map[string]any{"mode": "pool", "poolName": "sandboxes"},
				"client":        map[string]any{"proxyEnv": "HTTPS_PROXY", "caFileEnv": "SSL_CERT_FILE", "caSpkiEnv": "GATEHOUSE_CA_SPKI"}},
		},
		"pools": []any{
			map[string]any{"name": "cursor-workers", "namespace": "cursor", "serviceAccount": "worker"},
			map[string]any{"name": "claude-sessions", "namespace": "claude", "serviceAccount": "session", "identity": "claude-session", "ccpoolID": "ccpool_abc", "ceiling": "T1"},
			map[string]any{"name": "sandboxes", "namespace": "agent-sandboxes", "serviceAccount": "sandbox"},
		},
		"entries": []any{json.RawMessage(`{` + strings.Replace(entryBase, `"pools":["p"]`, `"pools":["cursor-workers","claude-sessions","sandboxes"]`, 1) + `}`)},
	}
}

func parseCatalog(t *testing.T, c map[string]any) (Catalog, error) {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return Parse(data)
}

func harnessAt(c map[string]any, i int) map[string]any {
	return c["harnesses"].([]any)[i].(map[string]any)
}

func TestHarnessProfilesLoad(t *testing.T) {
	catalog, err := parseCatalog(t, harnessCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(catalog.Harnesses()); n != 3 {
		t.Fatalf("%d harnesses", n)
	}
	for pool, want := range map[string]struct{ kind, mode, requester string }{
		"cursor-workers":  {IdentityPodToken, AuthorizePool, ""},
		"claude-sessions": {IdentitySessionJWT, AuthorizePerson, RequesterSessionJWT},
		"sandboxes":       {IdentityProxyAttested, AuthorizePool, ""},
	} {
		p, ok := catalog.Pool(pool)
		profile := p.Profile()
		if !ok || !profile.Explicit || profile.Identity.Kind != want.kind || profile.Authorization.Mode != want.mode || profile.RequesterKind() != want.requester {
			t.Errorf("%s: %+v", pool, profile)
		}
	}
}

// A catalog with no harnesses keeps working: each pool's profile is derived
// from its identity, as the broker behaved before profiles.
func TestPoolsWithoutHarnessesDeriveTheirProfile(t *testing.T) {
	c := harnessCatalog()
	delete(c, "harnesses")
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	cursor, _ := catalog.Pool("cursor-workers")
	claude, _ := catalog.Pool("claude-sessions")
	if p := cursor.Profile(); p.Explicit || p.Identity.Kind != IdentityPodToken || p.Path.Kind != PathSidecar || p.Authorization.Mode != AuthorizePool || p.RequesterKind() != "" {
		t.Errorf("cursor: %+v", p)
	}
	if p := claude.Profile(); p.Explicit || p.Identity.Kind != IdentitySessionJWT || p.Authorization.Mode != AuthorizePerson || p.RequesterKind() != RequesterSessionJWT {
		t.Errorf("claude: %+v", p)
	}
	if p := (Pool{}).Profile(); p.Identity.Kind != IdentityPodToken || p.Authorization.Mode != AuthorizePool {
		t.Errorf("undefined pool: %+v", p)
	}
}

// Every missing or contradictory field refuses the whole catalog.
func TestIncompleteOrContradictoryHarnessIsRefused(t *testing.T) {
	cases := map[string]func(c map[string]any){
		"no name":         func(c map[string]any) { delete(harnessAt(c, 0), "name") },
		"duplicate name":  func(c map[string]any) { harnessAt(c, 1)["name"] = "cursor" },
		"no trust domain": func(c map[string]any) { delete(harnessAt(c, 0), "trustDomain") },
		"no issuer": func(c map[string]any) {
			harnessAt(c, 0)["trustDomain"] = map[string]any{"keys": "in-cluster", "audience": "gatehouse"}
		},
		"plain HTTP issuer": func(c map[string]any) {
			harnessAt(c, 0)["trustDomain"].(map[string]any)["issuer"] = "http://issuer.example"
		},
		"issuer with a query": func(c map[string]any) {
			harnessAt(c, 0)["trustDomain"].(map[string]any)["issuer"] = "https://issuer.example/?x=1"
		},
		"unknown keys source":   func(c map[string]any) { harnessAt(c, 0)["trustDomain"].(map[string]any)["keys"] = "static" },
		"no audience":           func(c map[string]any) { delete(harnessAt(c, 0)["trustDomain"].(map[string]any), "audience") },
		"no identity kind":      func(c map[string]any) { delete(harnessAt(c, 0)["identity"].(map[string]any), "kind") },
		"unknown identity kind": func(c map[string]any) { harnessAt(c, 0)["identity"].(map[string]any)["kind"] = "api-key" },
		"no owner kind":         func(c map[string]any) { delete(harnessAt(c, 0)["identity"].(map[string]any), "ownerKind") },
		"lower-case owner kind": func(c map[string]any) { harnessAt(c, 0)["identity"].(map[string]any)["ownerKind"] = "sandbox" },
		"no namespaces":         func(c map[string]any) { harnessAt(c, 0)["identity"].(map[string]any)["namespaces"] = []any{} },
		"repeated namespace": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["namespaces"] = []any{"cursor", "cursor"}
		},
		"no image digests": func(c map[string]any) { delete(harnessAt(c, 0)["identity"].(map[string]any), "imageDigests") },
		"image tag, not a digest": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["imageDigests"] = []any{"worker:latest"}
		},
		"unknown requester": func(c map[string]any) {
			harnessAt(c, 1)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "header"}
		},
		"no path":          func(c map[string]any) { delete(harnessAt(c, 0), "path") },
		"unknown path":     func(c map[string]any) { harnessAt(c, 0)["path"] = map[string]any{"kind": "direct"} },
		"no authorization": func(c map[string]any) { delete(harnessAt(c, 0), "authorization") },
		"unknown mode":     func(c map[string]any) { harnessAt(c, 0)["authorization"].(map[string]any)["mode"] = "anyone" },
		"no pool name":     func(c map[string]any) { delete(harnessAt(c, 0)["authorization"].(map[string]any), "poolName") },
		"undefined pool":   func(c map[string]any) { harnessAt(c, 0)["authorization"].(map[string]any)["poolName"] = "nobody" },
		"pool in two harnesses": func(c map[string]any) {
			harnessAt(c, 2)["authorization"].(map[string]any)["poolName"] = "cursor-workers"
		},
		"pool without a harness": func(c map[string]any) { c["harnesses"] = c["harnesses"].([]any)[:2] },
		"namespace not listed":   func(c map[string]any) { harnessAt(c, 0)["identity"].(map[string]any)["namespaces"] = []any{"other"} },
		"unknown field":          func(c map[string]any) { harnessAt(c, 0)["identity"].(map[string]any)["trustEveryone"] = true },
		"pod token on a shared proxy": func(c map[string]any) {
			harnessAt(c, 0)["path"] = map[string]any{"kind": "shared-proxy"}
		},
		"pod token deciding per person": func(c map[string]any) {
			harnessAt(c, 0)["authorization"].(map[string]any)["mode"] = "person"
		},
		"pod token with a requester": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "session-jwt"}
		},
		"session deciding for the pool": func(c map[string]any) {
			harnessAt(c, 1)["authorization"].(map[string]any)["mode"] = "pool"
		},
		"session with a signed assertion": func(c map[string]any) {
			harnessAt(c, 1)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "signed-assertion"}
		},
		"proxy-attested behind a sidecar": func(c map[string]any) {
			harnessAt(c, 2)["path"] = map[string]any{"kind": "sidecar", "crossCluster": true}
		},
		"proxy-attested with a session token": func(c map[string]any) {
			harnessAt(c, 2)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "session-jwt"}
		},
		"signed assertion before the broker verifies one": func(c map[string]any) {
			harnessAt(c, 2)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "signed-assertion"}
		},
		"person without a requester": func(c map[string]any) {
			harnessAt(c, 2)["authorization"].(map[string]any)["mode"] = "person"
		},
		"cross cluster with in-cluster keys": func(c map[string]any) {
			harnessAt(c, 2)["trustDomain"].(map[string]any)["keys"] = "in-cluster"
		},
		"proxy-attested over two namespaces": func(c map[string]any) {
			harnessAt(c, 2)["identity"].(map[string]any)["namespaces"] = []any{"agent-sandboxes", "other"}
		},
		"one namespace in two proxy-attested harnesses": func(c map[string]any) {
			second := map[string]any{}
			b, _ := json.Marshal(harnessAt(c, 2))
			_ = json.Unmarshal(b, &second)
			second["name"] = "agent-sandbox-2"
			second["authorization"] = map[string]any{"mode": "pool", "poolName": "sandboxes-2"}
			c["harnesses"] = append(c["harnesses"].([]any), second)
			c["pools"] = append(c["pools"].([]any), map[string]any{"name": "sandboxes-2", "namespace": "agent-sandboxes", "serviceAccount": "sandbox", "ceiling": "external"})
		},
		"remote keys on one cluster": func(c map[string]any) {
			harnessAt(c, 2)["path"].(map[string]any)["crossCluster"] = false
		},
		"pod token across clusters": func(c map[string]any) {
			harnessAt(c, 0)["trustDomain"].(map[string]any)["keys"] = "remote"
			harnessAt(c, 0)["path"].(map[string]any)["crossCluster"] = true
		},
		"pool identity disagrees with mode": func(c map[string]any) {
			c["pools"].([]any)[1].(map[string]any)["identity"] = "workload"
			delete(c["pools"].([]any)[1].(map[string]any), "ccpoolID")
		},
	}
	for name, mutate := range cases {
		c := harnessCatalog()
		mutate(c)
		if _, err := parseCatalog(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// One shared proxy serves customer and developer sandboxes as two profiles:
// the customer one at the external ceiling with no entries, the developer
// one with its own pool and grants.
func TestCustomerAndDeveloperSandboxProfiles(t *testing.T) {
	c := harnessCatalog()
	orion := map[string]any{}
	b, _ := json.Marshal(harnessAt(c, 2))
	_ = json.Unmarshal(b, &orion)
	orion["name"] = "agent-sandbox-orion"
	orion["identity"].(map[string]any)["namespaces"] = []any{"orion-sandboxes"}
	orion["authorization"] = map[string]any{"mode": "pool", "poolName": "orion"}
	c["harnesses"] = append(c["harnesses"].([]any), orion)
	c["pools"] = append(c["pools"].([]any), map[string]any{"name": "orion", "namespace": "orion-sandboxes", "serviceAccount": "sandbox", "ceiling": "external"})
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := catalog.Pool("orion")
	if pool.Ceiling != CeilingExternal || pool.Profile().Name != "agent-sandbox-orion" {
		t.Fatalf("orion: %+v", pool)
	}
	// Granting the customer pool anything refuses the catalog.
	c["entries"] = []any{json.RawMessage(`{` + strings.Replace(entryBase, `"pools":["p"]`, `"pools":["sandboxes","orion"]`, 1) + `}`)}
	if _, err := parseCatalog(t, c); err == nil {
		t.Fatal("an entry granted to the customer sandboxes' external pool was accepted")
	}
}

// A proxy-attested harness may admit images by an agent-sandbox repository
// path instead of digests; two harnesses may never claim overlapping paths.
func TestHarnessImagePrefixes(t *testing.T) {
	const orion = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/"
	c := harnessCatalog()
	id := harnessAt(c, 2)["identity"].(map[string]any)
	id["imagePrefix"] = orion
	delete(id, "imageDigests")
	if _, err := parseCatalog(t, c); err != nil {
		t.Fatalf("prefix without digests refused: %v", err)
	}
	for name, mutate := range map[string]func(c map[string]any){
		"prefix on a pod-token harness": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["imagePrefix"] = "us-central1-docker.pkg.dev/trm-agent-sandbox/cursor/"
		},
		"another project": func(c map[string]any) {
			harnessAt(c, 2)["identity"].(map[string]any)["imagePrefix"] = "us-central1-docker.pkg.dev/other/agent-sandbox-images-staging/orion/"
		},
		"the whole project": func(c map[string]any) {
			harnessAt(c, 2)["identity"].(map[string]any)["imagePrefix"] = "us-central1-docker.pkg.dev/trm-agent-sandbox/"
		},
		"overlapping prefixes": func(c map[string]any) {
			second := map[string]any{}
			b, _ := json.Marshal(harnessAt(c, 2))
			_ = json.Unmarshal(b, &second)
			second["name"] = "agent-sandbox-2"
			second["identity"].(map[string]any)["namespaces"] = []any{"other-sandboxes"}
			second["identity"].(map[string]any)["imagePrefix"] = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/"
			second["authorization"] = map[string]any{"mode": "pool", "poolName": "sandboxes-2"}
			c["harnesses"] = append(c["harnesses"].([]any), second)
			c["pools"] = append(c["pools"].([]any), map[string]any{"name": "sandboxes-2", "namespace": "other-sandboxes", "serviceAccount": "sandbox", "ceiling": "external"})
		},
	} {
		cc := harnessCatalog()
		ccid := harnessAt(cc, 2)["identity"].(map[string]any)
		ccid["imagePrefix"] = orion
		delete(ccid, "imageDigests")
		mutate(cc)
		if _, err := parseCatalog(t, cc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Pinned keys are another cluster's keys, as remote ones are.
func TestHarnessPinnedKeys(t *testing.T) {
	c := harnessCatalog()
	harnessAt(c, 2)["trustDomain"].(map[string]any)["keys"] = "pinned"
	if _, err := parseCatalog(t, c); err != nil {
		t.Fatalf("pinned cross-cluster harness refused: %v", err)
	}
	harnessAt(c, 2)["path"].(map[string]any)["crossCluster"] = false
	if _, err := parseCatalog(t, c); err == nil {
		t.Fatal("pinned keys on a same-cluster path accepted")
	}
}

// One harness may serve a namespace per tenant: 10,000 load, one more is
// refused as malformed.
func TestHarnessServesTenThousandNamespaces(t *testing.T) {
	for n, ok := range map[int]bool{10000: true, 10001: false} {
		c := harnessCatalog()
		namespaces := []any{"cursor"}
		for i := 1; i < n; i++ {
			namespaces = append(namespaces, fmt.Sprintf("tenant-%d", i))
		}
		harnessAt(c, 0)["identity"].(map[string]any)["namespaces"] = namespaces
		if _, err := parseCatalog(t, c); (err == nil) != ok {
			t.Errorf("%d namespaces: %v", n, err)
		}
	}
}

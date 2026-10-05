package httpcatalog

import (
	"encoding/json"
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
				"authorization": map[string]any{"mode": "pool", "poolName": "cursor-workers"}},
			map[string]any{"name": "claude", "trustDomain": inCluster,
				"identity":      map[string]any{"kind": "session-jwt", "ownerKind": "Job", "namespaces": []any{"claude"}, "imageDigests": []any{digestA}, "requester": map[string]any{"kind": "session-jwt"}},
				"path":          map[string]any{"kind": "sidecar"},
				"authorization": map[string]any{"mode": "person", "poolName": "claude-sessions"}},
			map[string]any{"name": "agent-sandbox", "trustDomain": map[string]any{"issuer": "https://container.googleapis.com/v1/projects/s/locations/l/clusters/sandbox", "keys": "remote", "audience": "gatehouse"},
				"identity":      map[string]any{"kind": "proxy-attested", "ownerKind": "Sandbox", "namespaces": []any{"agent-sandboxes"}, "imageDigests": []any{digestB}},
				"path":          map[string]any{"kind": "shared-proxy", "crossCluster": true},
				"authorization": map[string]any{"mode": "pool", "poolName": "sandboxes"}},
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

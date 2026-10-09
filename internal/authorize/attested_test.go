package authorize

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// attestedPools is two agent-sandbox namespaces behind one shared proxy: one
// decides per person from the attested requester, the other for the pool.
func attestedPools(t *testing.T) (person, pool httpcatalog.Pool) {
	t.Helper()
	domain := `"trustDomain":{"issuer":"https://container.googleapis.com/v1/projects/s/locations/l/clusters/sandbox","keys":"remote","audience":"gatehouse"}`
	harness := func(name, namespace, requester, mode string) string {
		return `{"name":"` + name + `",` + domain + `,"identity":{"kind":"proxy-attested","ownerKind":"Sandbox","namespaces":["` + namespace + `"],"imageDigests":["` + digest + `"]` + requester + `},` +
			`"path":{"kind":"shared-proxy","crossCluster":true},"authorization":{"mode":"` + mode + `","poolName":"` + name + `"},"client":{"proxyEnv":"HTTPS_PROXY","caFileEnv":"SSL_CERT_FILE"}}`
	}
	catalog, err := httpcatalog.Parse([]byte(`{"harnesses":[` +
		harness("developers", "dev-sandboxes", `,"requester":{"kind":"pod-annotation"}`, "person") + `,` +
		harness("shared", "shared-sandboxes", "", "pool") + `],
		"pools":[{"name":"developers","namespace":"dev-sandboxes","serviceAccount":"sandbox","identity":"attested-person","ceiling":"T2"},
			{"name":"shared","namespace":"shared-sandboxes","serviceAccount":"sandbox"}],
		"entries":[{"name":"vendor","host":"api.vendor.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["developers","shared"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	person, _ = catalog.Pool("developers")
	pool, _ = catalog.Pool("shared")
	return person, pool
}

func TestAttestedRequesterNamesThePerson(t *testing.T) {
	person, pool := attestedPools(t)
	ctx := context.Background()
	persons := runnerid.Verifiers{SandboxDomains: []string{"example.org"}}
	b := &authorizetest.MemBinder{}
	resolve := func(p httpcatalog.Pool, session, requester string, v Verifier) (Requester, string) {
		return Resolve(ctx, p, session, Claims{Pod: "pod-a", AttestedRequester: requester}, v, b)
	}
	if who, refusal := resolve(person, "", "alice.smith@example.org", persons); refusal != "" || who.Kind != "person" || who.Subject != "alice.smith@example.org" {
		t.Fatalf("attested person: %+v %q", who, refusal)
	}
	// Another domain names nobody: T0 at most.
	if who, refusal := resolve(person, "", "alice@example.com", persons); refusal != "" || who.Kind != "none" {
		t.Fatalf("outside the domains: %+v %q", who, refusal)
	}
	for name, c := range map[string]struct {
		pool      httpcatalog.Pool
		session   string
		requester string
		v         Verifier
		want      string
	}{
		"no requester on a person profile":    {person, "", "", persons, "requester_missing"},
		"no domains configured":               {person, "", "alice.smith@example.org", runnerid.Verifiers{}, "requester_unverifiable"},
		"no verifier at all":                  {person, "", "alice.smith@example.org", nil, "requester_unverifiable"},
		"a verifier without attested persons": {person, "", "alice.smith@example.org", oneToken{}, "requester_unverifiable"},
		"a requester on a pool profile":       {pool, "", "alice.smith@example.org", persons, "requester_unexpected"},
		"a session token through the proxy":   {person, "alice", "alice.smith@example.org", persons, "session_unexpected"},
	} {
		who, refusal := resolve(c.pool, c.session, c.requester, c.v)
		if refusal != c.want || who.Kind != "none" || who.Subject != "" {
			t.Errorf("%s: %+v %q, want %q", name, who, refusal, c.want)
		}
	}
	// A pool profile with no requester is unchanged.
	if who, refusal := resolve(pool, "", "", persons); refusal != "" || who.Kind != "none" {
		t.Fatalf("pool profile: %+v %q", who, refusal)
	}
	// A requester reaching a Claude pool is refused, not ignored.
	_, explicit := profiledPools(t)
	claude, _ := explicit.Pool("claude")
	if _, refusal := resolve(claude, "alice", "alice.smith@example.org", oneToken{}); refusal != "requester_unexpected" {
		t.Fatalf("claude pool: %q", refusal)
	}
}

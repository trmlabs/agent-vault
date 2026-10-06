package httpcatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type scriptedLoader struct {
	mu      sync.Mutex
	doc     string
	version int
	err     error
	loads   int
}

func (l *scriptedLoader) set(doc string, version int, err error) {
	l.mu.Lock()
	l.doc, l.version, l.err = doc, version, err
	l.mu.Unlock()
}

func (l *scriptedLoader) load(context.Context) ([]byte, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loads++
	return []byte(l.doc), l.version, l.err
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
	}
}

func TestSourceSwapsValidVersionsAndKeepsLastGood(t *testing.T) {
	v1 := `{"entries":[` + validEntry + `]}`
	loader := &scriptedLoader{doc: v1, version: 1}
	source, err := Open(context.Background(), loader.load)
	if err != nil || source.Version() != 1 || !source.Current().HasHost("serpapi.com", 443) {
		t.Fatalf("open: %v", err)
	}
	var mu sync.Mutex
	var rejected []int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var changes atomic.Int32
	source.OnChange(func(Catalog) { changes.Add(1) })
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(version int, err error) {
		mu.Lock()
		rejected = append(rejected, version)
		mu.Unlock()
		if strings.Contains(err.Error(), "synthetic") {
			t.Error("rejection carried catalog content")
		}
	})
	// A broken version is refused once and the previous catalog stays.
	loader.set(`{"entries":[{"name":"x","host":"*.synthetic.example"}]}`, 2, nil)
	waitFor(t, "rejection", func() bool { mu.Lock(); defer mu.Unlock(); return len(rejected) > 0 })
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if len(rejected) != 1 || rejected[0] != 2 {
		t.Fatalf("rejections %v, want one for version 2", rejected)
	}
	mu.Unlock()
	if source.Version() != 1 || !source.Current().HasHost("serpapi.com", 443) {
		t.Fatal("a broken version replaced the last good catalog")
	}
	// A valid version is swapped in.
	loader.set(strings.Replace(v1, `"serpapi.com"`, `"api.serpapi.com"`, 1), 3, nil)
	waitFor(t, "swap", func() bool { return source.Version() == 3 })
	if !source.Current().HasHost("api.serpapi.com", 443) || source.Current().HasHost("serpapi.com", 443) {
		t.Fatal("new catalog not in force")
	}
	// Each swapped-in version is announced once; the refused one is not.
	waitFor(t, "change hook", func() bool { return changes.Load() == 1 })
	// Vault unreachable: reported, catalog kept.
	loader.set("", 0, errors.New("sealed"))
	waitFor(t, "load failure", func() bool { mu.Lock(); defer mu.Unlock(); return len(rejected) > 1 })
	if source.Version() != 3 {
		t.Fatal("load failure changed the catalog")
	}
	if _, err := Open(context.Background(), (&scriptedLoader{doc: `{"entries":[]}`, version: 1}).load); err == nil {
		t.Fatal("startup accepted an invalid catalog")
	}
}

type catalogVault struct{ doc string }

func (v catalogVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	if path != "gatehouse/data/catalog" {
		return nil, errors.New("wrong path")
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{"catalog": v.doc}, "metadata": map[string]interface{}{"version": float64(7)}}}, nil
}

func TestVaultLoaderAndYAML(t *testing.T) {
	yamlDoc := "entries:\n  - name: serpapi\n    host: serpapi.com\n    pathPrefixes: [/search]\n    methods: [GET]\n    header: X-Api-Key\n" +
		"    placeholder: __vault_SERPAPI_KEY__\n    key: {mount: gatehouse, path: vendors/serpapi, field: key}\n    pools: [pool-a]\n"
	doc, err := FromYAML([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	source, err := Open(context.Background(), VaultLoader(catalogVault{doc: string(doc)}, "gatehouse", "catalog", "catalog"))
	if err != nil || source.Version() != 7 || !source.Current().HasHost("serpapi.com", 443) {
		t.Fatalf("vault catalog: %v", err)
	}
	if _, err := Open(context.Background(), VaultLoader(catalogVault{}, "gatehouse", "catalog", "catalog")); err == nil {
		t.Fatal("empty catalog document accepted")
	}
	if _, err := FromYAML([]byte("entries: [")); err == nil {
		t.Fatal("broken YAML accepted")
	}
}

func TestPoolsAndPostgresEntries(t *testing.T) {
	doc := `{"pools":[{"name":"pool-a","namespace":"agents","serviceAccount":"worker"}],"entries":[` + validEntry + `,
		{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"core","mount":"database","role":"r-readonly"}}]}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if e, err := c.Database("core", "pool-a"); err != nil || e.Port != 5432 || e.Postgres.SSLMode != "verify-full" || c.HasHost(e.Host, 5432) {
		t.Fatalf("postgres entry: %+v %v", e, err)
	}
	if _, err := c.Database("core", "pool-b"); !errors.Is(err, ErrPool) {
		t.Fatal("ungranted pool")
	}
	if err := c.CheckHosts([]string{".postgresbridge.com", "serpapi.com"}); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckHosts([]string{".postgresbridge.com"}); err == nil {
		t.Fatal("host outside the allowed domains accepted")
	}
	for name, bad := range map[string]string{
		"undefined pool":     strings.Replace(doc, `"pools":["pool-a"],"postgres"`, `"pools":["pool-z"],"postgres"`, 1),
		"duplicate pool":     strings.Replace(doc, `"pools":[{"name":"pool-a"`, `"pools":[{"name":"pool-a","namespace":"x","serviceAccount":"y"},{"name":"pool-a"`, 1),
		"bad sslmode":        strings.Replace(doc, `"role":"r-readonly"`, `"role":"r-readonly","sslmode":"allow"`, 1),
		"no role":            strings.Replace(doc, `"role":"r-readonly"`, `"role":""`, 1),
		"header on postgres": strings.Replace(doc, `"kind":"postgres",`, `"kind":"postgres","header":"X-Api-Key",`, 1),
		"postgres sans kind": strings.Replace(doc, `"kind":"postgres",`, ``, 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Catalog databases are reached with verify-full only: the other modes skip
// the certificate check, so someone on the path could relay SCRAM. Only a
// test harness with a TLS-less fixture may allow disable, and never require.
func TestCatalogDatabasesUseVerifyFull(t *testing.T) {
	doc := `{"pools":[{"name":"pool-a","namespace":"agents","serviceAccount":"worker"}],"entries":[` + validEntry + `,
		{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"core","mount":"database","role":"r-readonly","sslmode":"MODE"}}]}`
	mode := func(m string) error { _, err := Parse([]byte(strings.Replace(doc, "MODE", m, 1))); return err }
	if err := mode("verify-full"); err != nil {
		t.Fatalf("verify-full refused: %v", err)
	}
	for _, m := range []string{"disable", "allow", "prefer", "require", "verify-ca"} {
		if mode(m) == nil {
			t.Errorf("sslmode %s accepted", m)
		}
	}
	plaintextDatabases.Store(true) // what an e2e build's AllowPlaintextDatabases sets
	t.Cleanup(func() { plaintextDatabases.Store(false) })
	if mode("disable") == nil {
		t.Fatal("the test harness switch allowed plaintext to a public host")
	}
	local := func(m string) error {
		_, err := Parse([]byte(strings.Replace(strings.Replace(doc, "MODE", m, 1), "p.abc.db.postgresbridge.com", "fixture-db.gatehouse.svc.cluster.local", 1)))
		return err
	}
	if err := local("disable"); err != nil {
		t.Fatalf("test harness switch did not allow disable to a cluster Service: %v", err)
	}
	if local("require") == nil {
		t.Fatal("the test harness switch allowed require")
	}
}

// A ";" in a prefix would let a granted prefix name a path parameter.
func TestPathPrefixesRefuseSemicolons(t *testing.T) {
	bad := strings.Replace(`{"entries":[`+validEntry+`]}`, `"pathPrefixes":["`, `"pathPrefixes":["/v1;x`, 1)
	if !strings.Contains(bad, "/v1;x") {
		t.Fatal("test document did not change")
	}
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("prefix with ; accepted")
	}
}

// Git grants answer per installation, repository and scope, so cached tokens
// can follow a catalog change.
func TestGitGranted(t *testing.T) {
	doc := `{"entries":[
		{"name":"git","kind":"git","host":"github.com","pools":["pool-a"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/a","access":"write"},{"repo":"trmlabs/b","access":"read"}]}},
		{"name":"api","kind":"github-api","host":"api.github.com","pools":["pool-a"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/a","access":"write"}]}}]}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		installation int64
		repo, scope  string
		want         bool
	}{
		{42, "trmlabs/a", "contents-write", true},
		{42, "TrmLabs/A", "contents-read", true},
		{42, "trmlabs/b", "contents-read", true},
		{42, "trmlabs/b", "contents-write", false},
		{42, "trmlabs/a", "pull-requests", true},
		{42, "trmlabs/b", "pull-requests", false},
		{43, "trmlabs/a", "contents-read", false},
		{42, "trmlabs/c", "contents-read", false},
	} {
		if got := c.GitGranted(tc.installation, tc.repo, tc.scope); got != tc.want {
			t.Errorf("GitGranted(%d, %s, %s) = %v, want %v", tc.installation, tc.repo, tc.scope, got, tc.want)
		}
	}
}

// GitScope lists every repository an installation's entries name, for the
// broker's installation scope check.
func TestGitScope(t *testing.T) {
	doc := `{"entries":[
		{"name":"git","kind":"git","host":"github.com","pools":["pool-a"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/a","access":"write"},{"repo":"trmlabs/b","access":"read"}]}},
		{"name":"other","kind":"git","host":"github.com","pools":["pool-b"],"git":{"appID":7,"installationID":43,"repos":[{"repo":"trmlabs/c","access":"read"}]}},
		{"name":"api","kind":"github-api","host":"api.github.com","pools":["pool-a"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/a","access":"write"}]}}]}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if repos, pullRequests := c.GitScope(42); fmt.Sprint(repos) != "[trmlabs/a trmlabs/b trmlabs/a]" || !pullRequests {
		t.Errorf("GitScope(42) = %v, %v", repos, pullRequests)
	}
	if repos, pullRequests := c.GitScope(43); fmt.Sprint(repos) != "[trmlabs/c]" || pullRequests {
		t.Errorf("GitScope(43) = %v, %v", repos, pullRequests)
	}
	if repos, _ := c.GitScope(44); repos != nil {
		t.Errorf("GitScope(44) = %v", repos)
	}
}

// The catalog refuses the strings the Terraform module refuses, since they
// end up in the broker's Vault policy.
func TestCatalogRefusesPolicyUnsafeStrings(t *testing.T) {
	keyDoc := func(mount, path string) string {
		return `{"entries":[{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search"],"methods":["GET"],"header":"X-Api-Key",
			"placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"` + mount + `","path":"` + path + `","field":"key"},"pools":["pool-a"]}]}`
	}
	if _, err := Parse([]byte(keyDoc("gatehouse", "vendors/serpapi"))); err != nil {
		t.Fatalf("valid key refused: %v", err)
	}
	for name, doc := range map[string]string{
		"star path":          keyDoc("gatehouse", "*"),
		"quote-injected":     keyDoc("gatehouse", `vendors/x\" } path \"sys/policies/acl/*`),
		"dot-dot":            keyDoc("gatehouse", "vendors/../stage/broker-owner"),
		"outside vendors":    keyDoc("gatehouse", "stage/broker-owner"),
		"plus mount":         keyDoc("gate+house", "vendors/serpapi"),
		"upper-case mount":   keyDoc("Gatehouse", "vendors/serpapi"),
		"long path":          keyDoc("gatehouse", "vendors/"+strings.Repeat("a", 127)),
		"vendors only":       keyDoc("gatehouse", "vendors"),
		"upper-case segment": keyDoc("gatehouse", "vendors/SerpApi"),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// With an environment set, roles must be that environment's named roles, and
// access is write exactly for -readwrite roles.
func TestCatalogDatabaseRolesAndAccess(t *testing.T) {
	doc := func(mount, role, access string) string {
		a := ""
		if access != "" {
			a = `,"access":"` + access + `"`
		}
		return `{"entries":[{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],
			"postgres":{"database":"core","mount":"` + mount + `","role":"` + role + `"` + a + `}}]}`
	}
	Environment.Store("staging")
	t.Cleanup(func() { Environment.Store("") })
	for name, tc := range map[string]struct {
		mount, role, access string
		ok                  bool
	}{
		"readonly default read": {"database", "staging.us.crunchy.core-readonly", "", true},
		"readwrite with write":  {"database", "staging.us.crunchy.core-readwrite", "write", true},
		"readwrite as read":     {"database", "staging.us.crunchy.core-readwrite", "", false},
		"readonly as write":     {"database", "staging.us.crunchy.core-readonly", "write", false},
		"bad access":            {"database", "staging.us.crunchy.core-readonly", "admin", false},
		"other environment":     {"database", "prod.us.crunchy.core-readonly", "", false},
		"gatehouse readonly":    {"database", "gatehouse-staging.us.crunchy.core-readonly", "", true},
		"gatehouse readwrite":   {"database", "gatehouse-staging.us.crunchy.core-readwrite", "write", true},
		"gatehouse as write":    {"database", "gatehouse-staging.us.crunchy.core-readonly", "write", false},
		"gatehouse other env":   {"database", "gatehouse-prod.us.crunchy.core-readonly", "", false},
		"gatehouse env suffix":  {"database", "gatehouse-stagingx.us.crunchy.core-readonly", "", false},
		"other prefix":          {"database", "agent-staging.us.crunchy.core-readonly", "", false},
		"doubled prefix":        {"database", "gatehouse-gatehouse-staging.us.crunchy.core-readonly", "", false},
		"no suffix":             {"database", "staging.us.crunchy.core", "", false},
		"bare role":             {"database", "readonly", "", false},
		"plus mount":            {"data+base", "staging.us.crunchy.core-readonly", "", false},
		"nested mount":          {"db/staging", "staging.us.crunchy.core-readonly", "", true},
	} {
		c, err := Parse([]byte(doc(tc.mount, tc.role, tc.access)))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, tc.ok)
			continue
		}
		if err == nil && tc.access == "" {
			if e, _ := c.Database("core", "pool-a"); e.Postgres.Access != "read" {
				t.Errorf("%s: access defaulted to %q, want read", name, e.Postgres.Access)
			}
		}
	}
	// Without an environment, a database entry is refused: an optional rule
	// fails closed. Only the e2e build keeps plain roles such as "readonly".
	Environment.Store("")
	rolesWithoutEnvironment = false
	t.Cleanup(func() { rolesWithoutEnvironment = true })
	if _, err := Parse([]byte(doc("database", "staging.us.crunchy.core-readonly", ""))); err == nil || !strings.Contains(err.Error(), "AGENT_VAULT_CATALOG_ENVIRONMENT") {
		t.Fatalf("database entry loaded with no environment set: %v", err)
	}
	if _, err := Parse([]byte(`{"entries":[` + validEntry + `]}`)); err != nil {
		t.Fatalf("a catalog with no database entries needs no environment: %v", err)
	}
	rolesWithoutEnvironment = true
	if _, err := Parse([]byte(doc("database", "readonly", ""))); err != nil {
		t.Fatalf("e2e build refused its plain fixture role: %v", err)
	}
}

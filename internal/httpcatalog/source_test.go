package httpcatalog

import (
	"context"
	"errors"
	"strings"
	"sync"
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

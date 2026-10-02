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

const validEntry = `{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search","/account/"],"methods":["get"],
	"header":"x-api-key","placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"vendors/serpapi","field":"key"},"pools":["pool-a"]}`

func entryWith(change string) string {
	return `{"entries":[` + strings.Replace(validEntry, `"pools":["pool-a"]`, `"pools":["pool-a"]`+change, 1) + `]}`
}

func TestParseNormalizesAndRejects(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + validEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.Port != 443 || e.Header != "X-Api-Key" || e.Methods[0] != "GET" || e.MaxRequestBytes != 1<<20 || e.MaxResponseBytes != 32<<20 {
		t.Fatalf("defaults: %+v", e)
	}
	for name, doc := range map[string]string{
		"wildcard host":      strings.Replace(entryWith(""), `"serpapi.com"`, `"*.serpapi.com"`, 1),
		"ip host":            strings.Replace(entryWith(""), `"serpapi.com"`, `"10.0.0.1"`, 1),
		"routing header":     strings.Replace(entryWith(""), `"x-api-key"`, `"X-Forwarded-Host"`, 1),
		"bad placeholder":    strings.Replace(entryWith(""), `__vault_SERPAPI_KEY__`, `SERPAPI`, 1),
		"traversal prefix":   strings.Replace(entryWith(""), `"/search"`, `"/a/../b"`, 1),
		"unsupported method": strings.Replace(entryWith(""), `["get"]`, `["CONNECT"]`, 1),
		"no pools":           strings.Replace(entryWith(""), `"pools":["pool-a"]`, `"pools":[]`, 1),
		"reserved forward":   entryWith(`,"forwardHeaders":["Cookie"]`),
		"unknown field":      entryWith(`,"insecure":true`),
		"oversized request":  entryWith(`,"maxRequestBytes":999999999`),
		"duplicate route":    `{"entries":[` + validEntry + `,` + strings.Replace(validEntry, `"serpapi"`, `"copy"`, 1) + `]}`,
		"trailing data":      `{"entries":[` + validEntry + `]} {}`,
		"empty":              `{"entries":[]}`,
		"key path traversal": strings.Replace(entryWith(""), `vendors/serpapi`, `vendors/../root`, 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMatchUsesSegmentsAndLongestPrefix(t *testing.T) {
	other := strings.NewReplacer(`"serpapi"`, `"serpapi-search-v2"`, `["/search","/account/"]`, `["/search/v2"]`, `["get"]`, `["post"]`).Replace(validEntry)
	c, err := Parse([]byte(`{"entries":[` + validEntry + `,` + other + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, method, path, pool, want string
		err                            error
	}{
		{"serpapi.com", "GET", "/search", "pool-a", "serpapi", nil},
		{"SERPAPI.com", "GET", "/search/json", "pool-a", "serpapi", nil},
		{"serpapi.com", "POST", "/search/v2/run", "pool-a", "serpapi-search-v2", nil},
		{"serpapi.com", "GET", "/account/me", "pool-a", "serpapi", nil},
		{"serpapi.com", "GET", "/searchable", "pool-a", "", ErrUnlisted},
		{"serpapi.com", "GET", "/account", "pool-a", "", ErrUnlisted},
		{"api.serpapi.com", "GET", "/search", "pool-a", "", ErrUnlisted},
		{"serpapi.com", "DELETE", "/search", "pool-a", "serpapi", ErrMethod},
		{"serpapi.com", "GET", "/search", "pool-b", "serpapi", ErrPool},
	} {
		e, err := c.Match(tc.host, 443, tc.method, tc.path, tc.pool)
		got := ""
		if e != nil {
			got = e.Name
		}
		if !errors.Is(err, tc.err) || got != tc.want {
			t.Errorf("%s %s %s: got %q %v", tc.method, tc.host, tc.path, got, err)
		}
	}
	if !c.HasHost("serpapi.com", 443) || c.HasHost("serpapi.com", 8443) || c.HasHost("example.com", 443) {
		t.Fatal("HasHost wrong")
	}
}

type fakeVault struct {
	mu      sync.Mutex
	value   string
	version int
	err     error
	reads   atomic.Int32
}

func (v *fakeVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	v.reads.Add(1)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return nil, fmt.Errorf("vault said: %s", v.value) // must never surface
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{"key": v.value}, "metadata": map[string]interface{}{"version": float64(v.version)}}}, nil
}

func (v *fakeVault) set(value string, version int, err error) {
	v.mu.Lock()
	v.value, v.version, v.err = value, version, err
	v.mu.Unlock()
}

func TestKeysCacheRotateAndFailClosed(t *testing.T) {
	ref := KeyRef{Mount: "gatehouse", Path: "vendors/serpapi", Field: "key"}
	vault := &fakeVault{value: "synthetic-key-one", version: 1}
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	keys := &Keys{Vault: vault, TTL: time.Minute, MaxStale: 5 * time.Minute, Now: func() time.Time { return now }}
	get := func() (Secret, error) { return keys.Get(context.Background(), ref) }

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = get() }()
	}
	wg.Wait()
	if vault.reads.Load() != 1 {
		t.Fatalf("concurrent misses read Vault %d times", vault.reads.Load())
	}
	vault.set("synthetic-key-two", 2, nil)
	if s, _ := get(); s.Value() != "synthetic-key-one" {
		t.Fatal("cache bypassed inside TTL")
	}
	now = now.Add(61 * time.Second)
	if s, _ := get(); s.Value() != "synthetic-key-two" || s.Version != 2 {
		t.Fatalf("rotation not picked up after TTL: v%d", s.Version)
	}
	vault.set("synthetic-key-three", 3, nil)
	keys.Invalidate(ref)
	if s, _ := get(); s.Version != 3 {
		t.Fatal("invalidate did not force a read")
	}
	now = now.Add(invalidateInterval)
	vault.set("synthetic-key-three", 3, errors.New("sealed"))
	now = now.Add(2 * time.Minute)
	if s, err := get(); err != nil || s.Version != 3 {
		t.Fatalf("stale key not served within MaxStale: %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, err := get(); !errors.Is(err, ErrKeyUnavailable) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("expired key served or leaked: %v", err)
	}
	for _, bad := range []string{"", "has space", "line\nbreak", strings.Repeat("k", 8193)} {
		vault.set(bad, 4, nil)
		now = now.Add(invalidateInterval)
		keys.Invalidate(ref)
		if _, err := get(); err == nil {
			t.Fatalf("unsafe key value accepted: %q", bad[:min(len(bad), 10)])
		}
	}
}

func TestSecretNeverPrints(t *testing.T) {
	vault := &fakeVault{value: "synthetic-key-print", version: 7}
	s, err := (&Keys{Vault: vault}).Get(context.Background(), KeyRef{Mount: "m", Path: "p", Field: "key"})
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q", s, s, s, s, s)} {
		if strings.Contains(out, "synthetic") || !strings.Contains(out, "http-key(v7)") {
			t.Fatalf("secret rendering %q", out)
		}
	}
}

// A vendor answering 401 to every call cannot turn each call into a Vault read.
func TestInvalidateIsRateLimitedPerKey(t *testing.T) {
	ref := KeyRef{Mount: "gatehouse", Path: "vendors/a", Field: "key"}
	other := KeyRef{Mount: "gatehouse", Path: "vendors/b", Field: "key"}
	vault := &fakeVault{value: "synthetic-key-limit", version: 1}
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	keys := &Keys{Vault: vault, Now: func() time.Time { return now }}
	if _, err := keys.Get(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	for range 100 { // a burst of rejected calls
		keys.Invalidate(ref)
		if _, err := keys.Get(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
		now = now.Add(100 * time.Millisecond)
	}
	if got := vault.reads.Load(); got != 2 {
		t.Fatalf("100 rejections inside 10s caused %d Vault reads, want 2", got)
	}
	keys.Invalidate(other) // limits are per key
	if _, err := keys.Get(context.Background(), other); err != nil || vault.reads.Load() != 3 {
		t.Fatalf("another key was throttled: reads=%d", vault.reads.Load())
	}
	now = now.Add(invalidateInterval)
	keys.Invalidate(ref)
	if _, err := keys.Get(context.Background(), ref); err != nil || vault.reads.Load() != 4 {
		t.Fatalf("refetch not allowed after the interval: reads=%d", vault.reads.Load())
	}
}

func TestTTLIsCappedAtOneMinute(t *testing.T) {
	ref := KeyRef{Mount: "gatehouse", Path: "vendors/a", Field: "key"}
	vault := &fakeVault{value: "synthetic-key-ttl", version: 1}
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	keys := &Keys{Vault: vault, TTL: time.Hour, Now: func() time.Time { return now }}
	_, _ = keys.Get(context.Background(), ref)
	now = now.Add(61 * time.Second)
	_, _ = keys.Get(context.Background(), ref)
	if vault.reads.Load() != 2 {
		t.Fatal("a TTL above one minute was honored")
	}
}

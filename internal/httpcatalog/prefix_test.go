package httpcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

// prefixVault serves a per-entry catalog from memory.
type prefixVault struct {
	mu          sync.Mutex
	head        map[string]interface{}
	headVersion int
	entries     map[string]string
	deleted     map[string]bool
	reads       atomic.Int64
}

func (v *prefixVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.reads.Add(1)
	v.mu.Lock()
	defer v.mu.Unlock()
	const base = "gatehouse/data/catalog/"
	var data map[string]interface{}
	switch {
	case path == base+"head":
		data = v.head
	case v.deleted[strings.TrimPrefix(path, base+"entries/")]:
		return &vaultapi.Secret{Data: map[string]interface{}{"data": nil,
			"metadata": map[string]interface{}{"version": float64(2), "deletion_time": "2026-10-06T00:00:00Z", "destroyed": false}}}, nil
	case strings.HasPrefix(path, base+"entries/"):
		if entry, ok := v.entries[strings.TrimPrefix(path, base+"entries/")]; ok {
			data = map[string]interface{}{"entry": entry}
		}
	}
	if data == nil {
		return nil, nil
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": float64(v.headVersion)}}}, nil
}

func (v *prefixVault) ListWithContext(_ context.Context, path string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if path != "gatehouse/metadata/catalog/entries" {
		return nil, nil
	}
	keys := make([]interface{}, 0, len(v.entries))
	for name := range v.entries {
		keys = append(keys, name)
	}
	for name := range v.deleted {
		keys = append(keys, name)
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"keys": keys}}, nil
}

func prefixEntry(name string) string {
	return strings.NewReplacer(`"serpapi"`, `"`+name+`"`, `"serpapi.com"`, `"`+name+`.example.com"`,
		`__vault_SERPAPI_KEY__`, `__vault_`+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))+`__`).Replace(validEntry)
}

func entriesDigest(entries map[string]string) string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name + "\n" + entries[name] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func newPrefixVault(n int) *prefixVault {
	v := &prefixVault{entries: map[string]string{}, headVersion: 1}
	for i := range n {
		name := fmt.Sprintf("e%05d", i)
		v.entries[name] = prefixEntry(name)
	}
	v.head = map[string]interface{}{"catalog": `{}`, "entries_sha256": entriesDigest(v.entries)}
	return v
}

func TestPrefixLoaderReadsTwentyThousandEntries(t *testing.T) {
	v := newPrefixVault(20000)
	raw, version, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background())
	if err != nil || version != 1 {
		t.Fatalf("load: version %d, %v", version, err)
	}
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries()) != 20000 || !c.HasHost("e19999.example.com", 443) {
		t.Fatalf("entries: %d", len(c.Entries()))
	}
}

func TestPrefixLoaderRefusesEntriesThatDoNotMatchTheHead(t *testing.T) {
	v := newPrefixVault(3)
	// An apply under way: one entry changed, the head not yet written.
	v.entries["e00001"] = strings.Replace(v.entries["e00001"], `"/search"`, `"/other"`, 1)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	v.head["entries_sha256"] = entriesDigest(v.entries)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err != nil {
		t.Fatalf("after the head caught up: %v", err)
	}
}

func TestPrefixLoaderRefusesAnEntryStoredUnderAnotherName(t *testing.T) {
	v := newPrefixVault(2)
	v.entries["e00001"] = prefixEntry("e00009")
	v.head["entries_sha256"] = entriesDigest(v.entries)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "another name") {
		t.Fatalf("misnamed entry accepted: %v", err)
	}
}

func TestPrefixLoaderRefusesAHeadThatCarriesEntries(t *testing.T) {
	v := newPrefixVault(1)
	v.head["catalog"] = `{"entries":[` + prefixEntry("smuggled") + `]}`
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "must not carry entries") {
		t.Fatalf("head entries accepted: %v", err)
	}
}

func TestPrefixLoaderRefusesAMissingEntryOrIncompleteHead(t *testing.T) {
	v := newPrefixVault(2)
	v.head["entries_sha256"] = "short"
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil {
		t.Fatal("incomplete head accepted")
	}
	v = newPrefixVault(2)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "other")(context.Background()); err == nil {
		t.Fatal("missing head accepted")
	}
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "../catalog")(context.Background()); err == nil {
		t.Fatal("bad prefix accepted")
	}
}

func TestPrefixLoaderSkipsEntryReadsWhileTheHeadIsUnchanged(t *testing.T) {
	v := newPrefixVault(50)
	load := VaultPrefixLoader(v, "gatehouse", "catalog")
	first, _, err := load(context.Background())
	if err != nil || v.reads.Load() != 51 {
		t.Fatalf("first load: %d reads, %v", v.reads.Load(), err)
	}
	again, version, err := load(context.Background())
	if err != nil || version != 1 || string(again) != string(first) || v.reads.Load() != 52 {
		t.Fatalf("unchanged head: %d reads, %v", v.reads.Load(), err)
	}
	v.headVersion = 2
	if _, version, err := load(context.Background()); err != nil || version != 2 || v.reads.Load() != 52+51 {
		t.Fatalf("new head: %d reads, %v", v.reads.Load(), err)
	}
}

func TestPrefixLoaderSkipsDeletedEntries(t *testing.T) {
	v := newPrefixVault(3)
	delete(v.entries, "e00001")
	v.deleted = map[string]bool{"e00001": true}
	v.head["entries_sha256"] = entriesDigest(v.entries)
	raw, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw)
	if err != nil || len(c.Entries()) != 2 || c.HasHost("e00001.example.com", 443) {
		t.Fatalf("deleted entry kept: %v", err)
	}
}

// A stray document fails the digest; the error names it, and what changed,
// against the last good catalog, so it can be found from the log.
func TestPrefixLoaderNamesWhatChangedOnAMismatch(t *testing.T) {
	v := newPrefixVault(3)
	load := VaultPrefixLoader(v, "gatehouse", "catalog")
	if _, _, err := load(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.headVersion = 2
	v.entries["stray"] = prefixEntry("stray")
	v.entries["e00001"] = strings.Replace(v.entries["e00001"], `"/search"`, `"/other"`, 1)
	delete(v.entries, "e00002")
	v.mu.Unlock()
	_, _, err := load(context.Background())
	if err == nil {
		t.Fatal("mismatch accepted")
	}
	for _, want := range []string{"listed 3", "added 1: stray", "changed 1: e00001", "removed 1: e00002"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "serpapi") || strings.Contains(err.Error(), "/other") {
		t.Errorf("error carries entry contents: %v", err)
	}
}

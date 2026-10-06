package httpcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
)

// ListLogical reads and lists KV version 2 secrets.
type ListLogical interface {
	Logical
	ListWithContext(ctx context.Context, path string) (*vaultapi.Secret, error)
}

// prefixReadConcurrency is how many entry secrets a reload reads at once.
// It sets reload speed, not how many entries the catalog may hold.
const prefixReadConcurrency = 64

// VaultPrefixLoader reads a catalog stored one secret per entry, so it is not
// bounded by Vault's size limit for one secret. Under mount/prefix:
//
//   - head: field "catalog" is the catalog document without "entries"; field
//     "entries_sha256" is the SHA-256, in lowercase hex, of each entry name in
//     byte order followed by a newline, its stored JSON and a newline.
//   - entries/<name>: field "entry" is that entry's JSON.
//
// Terraform writes the entries, then the head. The head's KV version is the
// catalog version, so a poll costs one read until the head changes. A reload
// whose entries do not match the head's digest, such as one read while an
// apply is under way, returns an error: the last good catalog stays in force
// and the next poll tries again.
func VaultPrefixLoader(vault ListLogical, mount, prefix string) Loader {
	var mu sync.Mutex
	var lastVersion int
	var last []byte
	return func(ctx context.Context) ([]byte, int, error) {
		if vault == nil || !kvPattern.MatchString(mount) || !kvPattern.MatchString(prefix) {
			return nil, 0, errors.New("catalog location is not configured")
		}
		head, version, err := readKV(ctx, vault, mount+"/data/"+prefix+"/head")
		if err != nil {
			return nil, 0, err
		}
		mu.Lock()
		defer mu.Unlock()
		if version == lastVersion {
			return last, version, nil
		}
		document, _ := head["catalog"].(string)
		want, _ := head["entries_sha256"].(string)
		if document == "" || len(want) != 64 {
			return nil, 0, errors.New("catalog head incomplete")
		}
		listing, err := vault.ListWithContext(ctx, mount+"/metadata/"+prefix+"/entries")
		if err != nil || listing == nil || listing.Data == nil {
			return nil, version, errors.New("catalog entry listing failed")
		}
		keys, _ := listing.Data["keys"].([]interface{})
		names := make([]string, 0, len(keys))
		for _, k := range keys {
			name, _ := k.(string)
			if !idPattern.MatchString(name) {
				return nil, version, fmt.Errorf("catalog entry key %q is not an entry name", name)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		stored, err := readEntries(ctx, vault, mount+"/data/"+prefix+"/entries/", names)
		if err != nil {
			return nil, version, err
		}
		listed := names
		names, entries := names[:0:0], make([]string, 0, len(stored))
		for i, entry := range stored {
			if entry != "" {
				names, entries = append(names, listed[i]), append(entries, entry)
			}
		}
		digest := sha256.New()
		for i, name := range names {
			digest.Write([]byte(name + "\n" + entries[i] + "\n"))
		}
		if hex.EncodeToString(digest.Sum(nil)) != want {
			return nil, version, errors.New("catalog entries do not match the head; retrying at the next poll")
		}
		out, err := assemble(document, names, entries)
		if err != nil {
			return nil, version, err
		}
		last, lastVersion = out, version
		return out, version, nil
	}
}

// errDeleted is a KV secret whose current version is deleted or destroyed.
// Vault still lists its key until its metadata is removed.
var errDeleted = errors.New("catalog secret deleted")

func readKV(ctx context.Context, vault Logical, path string) (map[string]interface{}, int, error) {
	resp, err := vault.ReadWithDataWithContext(ctx, path, nil)
	if err != nil || resp == nil || resp.Data == nil {
		return nil, 0, errors.New("catalog read failed")
	}
	data, _ := resp.Data["data"].(map[string]interface{})
	metadata, _ := resp.Data["metadata"].(map[string]interface{})
	version := 0
	switch n := metadata["version"].(type) {
	case json.Number:
		version, _ = strconv.Atoi(n.String())
	case float64:
		version = int(n)
	}
	if deleted, _ := metadata["deletion_time"].(string); data == nil && (deleted != "" || metadata["destroyed"] == true) {
		return nil, 0, errDeleted
	}
	if data == nil || version < 1 {
		return nil, 0, errors.New("catalog response incomplete")
	}
	return data, version, nil
}

// readEntries reads every entry's stored JSON, concurrently, in names order.
// A deleted entry reads as "": it is no longer in the catalog.
func readEntries(ctx context.Context, vault Logical, base string, names []string) ([]string, error) {
	out := make([]string, len(names))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var once sync.Once
	var failure error
	next := make(chan int)
	for range min(prefixReadConcurrency, max(len(names), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				data, _, err := readKV(ctx, vault, base+names[i])
				if errors.Is(err, errDeleted) {
					continue
				}
				entry, _ := data["entry"].(string)
				if err == nil && entry == "" {
					err = errors.New("catalog entry incomplete")
				}
				if err != nil {
					once.Do(func() { failure = fmt.Errorf("catalog entry %q: %w", names[i], err); cancel() })
					continue
				}
				out[i] = entry
			}
		}()
	}
	for i := range names {
		select {
		case next <- i:
		case <-ctx.Done():
		}
	}
	close(next)
	wg.Wait()
	if failure != nil {
		return nil, failure
	}
	return out, nil
}

// assemble rebuilds the one-document form Parse validates. Each entry's name
// must be the key it is stored under.
func assemble(document string, names, entries []string) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &top); err != nil {
		return nil, errors.New("catalog head is not a JSON object")
	}
	if _, ok := top["entries"]; ok {
		return nil, errors.New("catalog head must not carry entries")
	}
	var list bytes.Buffer
	list.WriteByte('[')
	for i, raw := range entries {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(raw), &named) != nil || named.Name != names[i] {
			return nil, fmt.Errorf("catalog entry %q is stored under another name", names[i])
		}
		if i > 0 {
			list.WriteByte(',')
		}
		list.WriteString(raw)
	}
	list.WriteByte(']')
	top["entries"] = list.Bytes()
	return json.Marshal(top)
}

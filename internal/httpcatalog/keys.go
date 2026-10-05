package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Logical is the Vault read the key cache needs; *vaultapi.Logical has it.
type Logical interface {
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vaultapi.Secret, error)
}

// Secret is a key value and its KV version. It prints as its version only.
type Secret struct {
	value   string
	Version int
}

func (s Secret) Value() string              { return s.value }
func (s Secret) String() string             { return fmt.Sprintf("http-key(v%d)", s.Version) }
func (s Secret) GoString() string           { return s.String() }
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }

// Keys caches each key for TTL, so the broker reads Vault about once a
// minute per key instead of once per request. A new KV version is picked up
// within TTL, or sooner after Invalidate. If Vault is unreachable, a cached
// key is served for up to MaxStale past its TTL, then requests fail.
type Keys struct {
	Vault    Logical
	TTL      time.Duration // default and maximum 1 minute
	MaxStale time.Duration // default 5 minutes
	Now      func() time.Time

	mu          sync.Mutex
	cache       map[KeyRef]cachedKey
	flight      map[KeyRef]*sync.Mutex
	invalidated map[KeyRef]time.Time
}

// invalidateInterval bounds vendor-triggered refetches: a vendor or attacker
// answering 401 to every call can cause at most one extra Vault read per key
// per interval.
const invalidateInterval = 30 * time.Second

type cachedKey struct {
	secret  Secret
	fetched time.Time
}

var ErrKeyUnavailable = errors.New("destination key unavailable")

func (k *Keys) settings() (time.Duration, time.Duration, time.Time) {
	ttl, stale, now := k.TTL, k.MaxStale, time.Now()
	if ttl <= 0 || ttl > time.Minute {
		ttl = time.Minute
	}
	if stale < 0 {
		stale = 0
	} else if stale == 0 {
		stale = 5 * time.Minute
	}
	if k.Now != nil {
		now = k.Now()
	}
	return ttl, stale, now
}

// Get returns the current key for ref. Concurrent misses for one key share a
// single Vault read.
func (k *Keys) Get(ctx context.Context, ref KeyRef) (Secret, error) {
	ttl, stale, now := k.settings()
	k.mu.Lock()
	if k.cache == nil {
		k.cache, k.flight = map[KeyRef]cachedKey{}, map[KeyRef]*sync.Mutex{}
	}
	if c, ok := k.cache[ref]; ok && now.Sub(c.fetched) < ttl {
		k.mu.Unlock()
		return c.secret, nil
	}
	lock, ok := k.flight[ref]
	if !ok {
		lock = &sync.Mutex{}
		k.flight[ref] = lock
	}
	k.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	k.mu.Lock()
	cached, have := k.cache[ref]
	k.mu.Unlock()
	if have && now.Sub(cached.fetched) < ttl {
		return cached.secret, nil // another request refreshed it while we waited
	}
	secret, err := k.read(ctx, ref)
	if err != nil {
		if have && now.Sub(cached.fetched) < ttl+stale {
			return cached.secret, nil
		}
		return Secret{}, ErrKeyUnavailable
	}
	k.mu.Lock()
	k.cache[ref] = cachedKey{secret: secret, fetched: now}
	k.mu.Unlock()
	return secret, nil
}

// Invalidate drops a cached key after the vendor rejects it, so the next
// request reads the newest version. It acts at most once per key every 30
// seconds; further calls in that window are ignored.
func (k *Keys) Invalidate(ref KeyRef) {
	_, _, now := k.settings()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.invalidated == nil {
		k.invalidated = map[KeyRef]time.Time{}
	}
	if last, ok := k.invalidated[ref]; ok && now.Sub(last) < invalidateInterval {
		return
	}
	k.invalidated[ref] = now
	delete(k.cache, ref)
}

// read never puts Vault's response or the key into an error.
func (k *Keys) read(ctx context.Context, ref KeyRef) (Secret, error) {
	if k.Vault == nil {
		return Secret{}, ErrKeyUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := k.Vault.ReadWithDataWithContext(ctx, ref.Mount+"/data/"+ref.Path, nil)
	if err != nil || resp == nil || resp.Data == nil {
		return Secret{}, ErrKeyUnavailable
	}
	data, _ := resp.Data["data"].(map[string]interface{})
	metadata, _ := resp.Data["metadata"].(map[string]interface{})
	value, _ := data[ref.Field].(string)
	if value == "" || len(value) > 8192 {
		return Secret{}, ErrKeyUnavailable
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return Secret{}, ErrKeyUnavailable // header-safe printable ASCII only
		}
	}
	version := 0
	switch n := metadata["version"].(type) {
	case json.Number:
		v, _ := strconv.Atoi(n.String())
		version = v
	case float64:
		version = int(n)
	}
	return Secret{value: value, Version: version}, nil
}

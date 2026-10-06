package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	keysMaxAge     = time.Hour
	refetchBackoff = 30 * time.Second
	minRSABits     = 2048
)

// jwks caches one issuer's signing keys, by kid, for an hour. An unknown kid
// or stale keys refetch at most every 30 seconds, one fetch at a time, and the
// last good set keeps serving within its hour when a fetch fails.
type jwks struct {
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	loaded    time.Time     // last successful fetch
	attempted time.Time     // last fetch attempt
	inflight  chan struct{} // closed when the fetch in progress ends
}

func (c *jwks) key(ctx context.Context, kid, url string, client *http.Client, now func() time.Time) crypto.PublicKey {
	c.mu.Lock()
	t := now()
	fresh := !c.loaded.IsZero() && t.Sub(c.loaded) < keysMaxAge
	if k := c.keys[kid]; k != nil && fresh {
		c.mu.Unlock()
		return k
	}
	// One fetch at a time, outside the lock: concurrent verifies wait for it
	// instead of each holding the lock across a network call.
	if wait := c.inflight; wait != nil {
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil
		}
		return c.current(kid, now)
	}
	if !c.attempted.IsZero() && t.Sub(c.attempted) < refetchBackoff {
		defer c.mu.Unlock()
		if fresh {
			return c.keys[kid]
		}
		return nil
	}
	c.attempted = t
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()
	// The caller's cancellation must not fail the refresh for everyone else.
	keys, err := fetchKeys(context.WithoutCancel(ctx), url, client)
	c.mu.Lock()
	if err == nil {
		c.keys, c.loaded = keys, t
	}
	c.inflight = nil
	close(done)
	c.mu.Unlock()
	return c.current(kid, now)
}

// current returns a key from the last good set while it is within its hour.
func (c *jwks) current(kid string, now func() time.Time) crypto.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded.IsZero() || now().Sub(c.loaded) >= keysMaxAge {
		return nil
	}
	return c.keys[kid]
}

// RefuseRedirects is an http.Client CheckRedirect that follows no redirect:
// the signing keys come only from the configured https URL.
func RefuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("runner JWKS redirect refused")
}

// fetchKeys reads a JWKS: P-256 keys for ES256 (Anthropic) and RSA keys of at
// least 2048 bits for RS256 (Cursor). Each verifier accepts only its own kind.
func fetchKeys(ctx context.Context, url string, client *http.Client) (map[string]crypto.PublicKey, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: RefuseRedirects}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("runner JWKS unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct{ Kty, Crv, Kid, Alg, Use, X, Y, N, E string } `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil {
		return nil, errors.New("invalid runner JWKS")
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		switch {
		case k.Kty == "EC" && k.Crv == "P-256" && (k.Alg == "" || k.Alg == "ES256"):
			x, ex := base64.RawURLEncoding.DecodeString(k.X)
			y, ey := base64.RawURLEncoding.DecodeString(k.Y)
			if ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
				continue
			}
			// Parsing the uncompressed point also rejects coordinates off the curve.
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				continue
			}
			keys[k.Kid] = pub
		case k.Kty == "RSA" && (k.Alg == "" || k.Alg == "RS256"):
			n, en := base64.RawURLEncoding.DecodeString(k.N)
			e, ee := base64.RawURLEncoding.DecodeString(k.E)
			if en != nil || ee != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			if pub.N.BitLen() < minRSABits || pub.N.BitLen() > 8192 || pub.E < 3 || pub.E%2 == 0 {
				continue
			}
			keys[k.Kid] = pub
		}
	}
	return keys, nil
}

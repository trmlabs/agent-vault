// Package runnerid verifies the Claude runner's session token locally and
// derives who is behind an agent session. The token proves which runner pool
// issued the session and, for human sessions, the person's SSO subject. It is
// never stored or logged; callers keep only its SHA-256.
package runnerid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	keysMaxAge     = time.Hour
	refetchBackoff = 30 * time.Second
	maxLifetime    = 12 * time.Hour
	clockSkew      = 60 * time.Second
	sessionRole    = "session_worker"
)

var ErrInvalid = errors.New("runner session token refused")

// Kind is who stands behind a session.
type Kind string

const (
	KindPerson Kind = "person" // a human, by SSO subject
	KindAgent  Kind = "agent"  // an agent:<id> session (for example a Slack-started one); no person
	KindNone   Kind = "none"   // no verified identity
)

// Session is a verified runner session.
type Session struct {
	Kind        Kind
	Subject     string   // act.attested_by.sub for a person; act.sub for an agent
	Pools       []string // ccpool_ IDs in the audience
	Expires     time.Time
	TokenSHA256 string
}

// InPool reports whether the token was issued for this runner pool.
func (s Session) InPool(ccpool string) bool {
	for _, p := range s.Pools {
		if p == ccpool {
			return true
		}
	}
	return false
}

// Verifier checks ES256 tokens against the issuer's JWKS, cached with rotation.
type Verifier struct {
	JWKSURL string
	Issuer  string
	Client  *http.Client
	Now     func() time.Time

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	loaded    time.Time // last successful fetch
	attempted time.Time // last fetch attempt
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

type claims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	Expires  int64           `json:"exp"`
	Issued   int64           `json:"iat"`
	NotBefor int64           `json:"nbf"`
	Role     string          `json:"ccr:role"`
	Act      struct {
		Sub        string `json:"sub"`
		AttestedBy struct {
			Sub string `json:"sub"`
		} `json:"attested_by"`
	} `json:"act"`
}

// Verify checks signature, issuer, role, lifetime and audience shape. It does
// not decide entitlement; that is a live per-request lookup elsewhere.
func (v *Verifier) Verify(ctx context.Context, token string) (Session, error) {
	if len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return Session{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Session{}, ErrInvalid
	}
	headerBytes, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(signature) != 64 {
		return Session{}, ErrInvalid
	}
	var header struct {
		Alg, Kid string
		Crit     []string
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "ES256" || header.Kid == "" || len(header.Crit) != 0 {
		return Session{}, ErrInvalid
	}
	key := v.key(ctx, header.Kid)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if key == nil || !ecdsa.Verify(key, digest[:], r, s) {
		return Session{}, ErrInvalid
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return Session{}, ErrInvalid
	}
	now := v.now()
	expires := time.Unix(c.Expires, 0)
	issued := time.Unix(c.Issued, 0)
	if c.Issuer != v.Issuer || c.Role != sessionRole || !now.Before(expires) || c.Issued <= 0 || issued.After(now.Add(clockSkew)) ||
		time.Unix(c.NotBefor, 0).After(now.Add(clockSkew)) || expires.Sub(issued) > maxLifetime {
		return Session{}, ErrInvalid
	}
	pools := audience(c.Audience)
	if len(pools) == 0 {
		return Session{}, ErrInvalid
	}
	sum := sha256.Sum256([]byte(token))
	session := Session{Kind: KindNone, Pools: pools, Expires: expires, TokenSHA256: hex.EncodeToString(sum[:])}
	switch {
	case strings.HasPrefix(c.Act.Sub, "agent:"):
		// No person behind it, whatever else the token says.
		session.Kind, session.Subject = KindAgent, c.Act.Sub
	case c.Act.AttestedBy.Sub != "":
		session.Kind, session.Subject = KindPerson, c.Act.AttestedBy.Sub
	}
	if len(session.Subject) > 256 || strings.ContainsAny(session.Subject, " \t\r\n\"\\") {
		return Session{}, ErrInvalid
	}
	return session, nil
}

// audience keeps only runner pool IDs from a string or list audience.
func audience(raw json.RawMessage) []string {
	var one string
	var many []string
	if json.Unmarshal(raw, &one) == nil {
		many = []string{one}
	} else if json.Unmarshal(raw, &many) != nil {
		return nil
	}
	var pools []string
	for _, a := range many {
		if strings.HasPrefix(a, "ccpool_") && len(a) <= 128 {
			pools = append(pools, a)
		}
	}
	return pools
}

func (v *Verifier) key(ctx context.Context, kid string) *ecdsa.PublicKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	fresh := !v.loaded.IsZero() && now.Sub(v.loaded) < keysMaxAge
	if k := v.keys[kid]; k != nil && fresh {
		return k
	}
	// An unknown kid or stale keys refetch, at most every 30 seconds.
	if !v.attempted.IsZero() && now.Sub(v.attempted) < refetchBackoff {
		if fresh {
			return v.keys[kid]
		}
		return nil
	}
	v.attempted = now
	keys, err := v.fetch(ctx)
	if err != nil {
		// Keep serving keys loaded within the last hour; never older ones.
		if fresh {
			return v.keys[kid]
		}
		return nil
	}
	v.keys, v.loaded = keys, now
	return keys[kid]
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
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
		Keys []struct{ Kty, Crv, Kid, Alg, Use, X, Y string } `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil {
		return nil, errors.New("invalid runner JWKS")
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" || (k.Alg != "" && k.Alg != "ES256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
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
	}
	return keys, nil
}

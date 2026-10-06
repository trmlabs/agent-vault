// Package runnerid verifies the Claude runner's session token locally and
// derives who is behind an agent session. The token proves which runner pool
// issued the session and who created it (Anthropic, "Verify session identity in
// self-hosted environments"): act.sub is user:<id> for a person or agent:<id>
// for the organization's service identity, and act.email is the person's
// address when the creating surface recorded one. act.attested_by is reserved
// and not read. A person is named by that email, as an Entra user principal
// name, only in a configured domain; without one the session has no person.
// The token is never stored or logged; callers keep only its SHA-256.
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
	// tokenPrefix marks a self-hosted runner session token. Hosted sessions carry
	// another sk-ant- prefix and other keys; those are refused outright.
	tokenPrefix = "sk-ant-cc-"
)

var ErrInvalid = errors.New("runner session token refused")

// Kind is who stands behind a session.
type Kind string

const (
	KindPerson Kind = "person" // a human, by email in a configured domain
	KindAgent  Kind = "agent"  // an agent:<id> session (for example a Slack-started one); no person
	KindNone   Kind = "none"   // no verified identity
)

// Session is a verified runner session.
type Session struct {
	Kind        Kind
	Subject     string   // the lower-cased act.email for a person; act.sub for an agent
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
	// PersonDomains are the lower-case email domains whose user sessions name a
	// person. Empty: no session names a person, so entries above T0 are refused.
	PersonDomains []string
	Client        *http.Client
	Now           func() time.Time

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	loaded    time.Time     // last successful fetch
	attempted time.Time     // last fetch attempt
	inflight  chan struct{} // closed when the fetch in progress ends
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
		Sub   string `json:"sub"`
		Email string `json:"email"`
	} `json:"act"`
}

// Verify checks signature, issuer, role, lifetime and audience shape. It does
// not decide entitlement; that is a live per-request lookup elsewhere.
func (v *Verifier) Verify(ctx context.Context, token string) (Session, error) {
	if len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return Session{}, ErrInvalid
	}
	// The runner's value carries the prefix; the JWT follows it. Any other
	// sk-ant- token (a hosted session's) is not one this broker can verify.
	raw := token
	if strings.HasPrefix(token, tokenPrefix) {
		token = strings.TrimPrefix(token, tokenPrefix)
	} else if strings.HasPrefix(token, "sk-ant-") {
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
	sum := sha256.Sum256([]byte(raw))
	session := Session{Kind: KindNone, Pools: pools, Expires: expires, TokenSHA256: hex.EncodeToString(sum[:])}
	switch {
	case strings.HasPrefix(c.Act.Sub, "agent:"):
		// No person behind it, whatever else the token says.
		session.Kind, session.Subject = KindAgent, c.Act.Sub
	case strings.HasPrefix(c.Act.Sub, "user:") && len(c.Act.Sub) > len("user:"):
		// A person only with a recorded email in a configured domain; otherwise
		// the session has no person and gets T0 at most.
		if email, ok := v.personEmail(c.Act.Email); ok {
			session.Kind, session.Subject = KindPerson, email
		}
	}
	if len(session.Subject) > 256 || strings.ContainsAny(session.Subject, " \"\\") || strings.ContainsFunc(session.Subject, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return Session{}, ErrInvalid
	}
	return session, nil
}

// personEmail is the lower-cased email when it is a single plain address in one
// of the configured domains.
func (v *Verifier) personEmail(email string) (string, bool) {
	email = strings.ToLower(email)
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at != strings.IndexByte(email, '@') || len(email) > 254 {
		return "", false
	}
	domain := email[at+1:]
	for _, d := range v.PersonDomains {
		if d != "" && domain == d {
			return email, true
		}
	}
	return "", false
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
	now := v.now()
	fresh := !v.loaded.IsZero() && now.Sub(v.loaded) < keysMaxAge
	if k := v.keys[kid]; k != nil && fresh {
		v.mu.Unlock()
		return k
	}
	// One fetch at a time, outside the lock: concurrent verifies wait for it
	// instead of each holding the lock across a network call.
	if wait := v.inflight; wait != nil {
		v.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil
		}
		return v.current(kid)
	}
	// An unknown kid or stale keys refetch, at most every 30 seconds.
	if !v.attempted.IsZero() && now.Sub(v.attempted) < refetchBackoff {
		defer v.mu.Unlock()
		if fresh {
			return v.keys[kid]
		}
		return nil
	}
	v.attempted = now
	done := make(chan struct{})
	v.inflight = done
	v.mu.Unlock()
	// The caller's cancellation must not fail the refresh for everyone else.
	keys, err := v.fetch(context.WithoutCancel(ctx))
	v.mu.Lock()
	if err == nil {
		v.keys, v.loaded = keys, now
	}
	v.inflight = nil
	close(done)
	v.mu.Unlock()
	// On failure the last good keys keep serving within their hour.
	return v.current(kid)
}

// current returns a key from the last good set while it is within its hour.
func (v *Verifier) current(kid string) *ecdsa.PublicKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.loaded.IsZero() || v.now().Sub(v.loaded) >= keysMaxAge {
		return nil
	}
	return v.keys[kid]
}

// RefuseRedirects is an http.Client CheckRedirect that follows no redirect:
// the signing keys come only from the configured https URL.
func RefuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("runner JWKS redirect refused")
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: RefuseRedirects}
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

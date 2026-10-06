// Package runnerid verifies the Claude runner's session token locally and
// derives who is behind an agent session. The token proves which runner pool
// issued the session and who created it (Anthropic, "Verify session identity in
// self-hosted environments"): act.sub is user:<id> for a person or agent:<id>
// for the organization's service identity, and act.email is the person's
// address when the creating surface recorded one. act.attested_by is reserved
// and not read. A person is named by that email, as an Entra user principal
// name, only in a configured domain; without one the session has no person.
// CursorVerifier does the same for a Cursor run's identity token (cursor.go).
// The token is never stored or logged; callers keep only its SHA-256.
package runnerid

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	maxLifetime = 12 * time.Hour
	clockSkew   = 60 * time.Second
	sessionRole = "session_worker"
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
	Subject     string   // the lower-cased email for a person; the owner for an agent
	Owner       string   // the vendor's stable owner (user:, agent: or service_account:), or ""
	Run         string   // the Cursor run (cloud_agent_id); "" for Claude
	Pools       []string // ccpool_ IDs in the audience (Claude)
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

	cache jwks
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
	if strings.HasPrefix(c.Act.Sub, "agent:") || strings.HasPrefix(c.Act.Sub, "user:") {
		session.Owner = c.Act.Sub
	}
	switch {
	case strings.HasPrefix(c.Act.Sub, "agent:"):
		// No person behind it, whatever else the token says.
		session.Kind, session.Subject = KindAgent, c.Act.Sub
	case strings.HasPrefix(c.Act.Sub, "user:") && len(c.Act.Sub) > len("user:"):
		// A person only with a recorded email in a configured domain; otherwise
		// the session has no person and gets T0 at most.
		if email, ok := personEmail(c.Act.Email, v.PersonDomains); ok {
			session.Kind, session.Subject = KindPerson, email
		}
	}
	if !plainSubject(session.Subject) || !plainSubject(session.Owner) {
		return Session{}, ErrInvalid
	}
	return session, nil
}

// plainSubject reports whether a value is short and safe to log and key on.
func plainSubject(s string) bool {
	return len(s) <= 256 && !strings.ContainsAny(s, " \"\\") && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// personEmail is the lower-cased email when it is a single plain address in one
// of the configured domains.
func personEmail(email string, domains []string) (string, bool) {
	email = strings.ToLower(email)
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at != strings.IndexByte(email, '@') || len(email) > 254 {
		return "", false
	}
	domain := email[at+1:]
	for _, d := range domains {
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
	k, _ := v.cache.key(ctx, kid, v.JWKSURL, v.Client, v.now).(*ecdsa.PublicKey)
	return k
}

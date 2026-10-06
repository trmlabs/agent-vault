package runnerid

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Cursor identity tokens (Cursor, "OIDC tokens"): a self-hosted worker started
// with --identity-socket mints an RS256 JWT for the claimed run over a local
// socket. Cursor fills the claims from the run, so a process on the worker
// cannot mint one for another run or another owner. sub is user:<id> for a
// person or service_account:<id> for a service account; owner_email is the
// person's lower-cased email when Cursor knows it.
const (
	CursorIssuer  = "https://api.cursor.com"
	CursorJWKSURL = "https://api.cursor.com/keys"
	// Cursor documents a 5-minute token; anything claiming over an hour is not one.
	cursorMaxLifetime = time.Hour
	cursorRuntime     = "self_hosted"
)

// CursorVerifier checks Cursor identity tokens minted on a self-hosted worker
// for this broker's audience and one of the configured Cursor teams.
type CursorVerifier struct {
	JWKSURL  string
	Issuer   string
	Audience string
	// TeamIDs are the Cursor team IDs whose runs may name anyone. Empty:
	// every token is refused.
	TeamIDs []string
	// PersonDomains are the lower-case email domains whose user runs name a
	// person. Empty: no run names a person, so entries above T0 are refused.
	PersonDomains []string
	Client        *http.Client
	Now           func() time.Time

	cache jwks
}

type cursorClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Expires  int64           `json:"exp"`
	Issued   int64           `json:"iat"`
	NotBefor int64           `json:"nbf"`
	Runtime  string          `json:"agent_runtime"`
	TeamID   string          `json:"team_id"`
	Email    string          `json:"owner_email"`
	RunID    string          `json:"cloud_agent_id"`
}

func (v *CursorVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks signature, issuer, audience, team, runtime and lifetime, and
// names the person behind the run. Like Verify for Claude, it does not decide
// entitlement.
func (v *CursorVerifier) Verify(ctx context.Context, token string) (Session, error) {
	if len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") || v.Audience == "" || len(v.TeamIDs) == 0 {
		return Session{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Session{}, ErrInvalid
	}
	headerBytes, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return Session{}, ErrInvalid
	}
	var header struct {
		Alg, Kid string
		Crit     []string
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Kid == "" || len(header.Crit) != 0 {
		return Session{}, ErrInvalid
	}
	key, _ := v.cache.key(ctx, header.Kid, v.JWKSURL, v.Client, v.now).(*rsa.PublicKey)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if key == nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Session{}, ErrInvalid
	}
	var c cursorClaims
	if json.Unmarshal(payload, &c) != nil {
		return Session{}, ErrInvalid
	}
	now := v.now()
	expires := time.Unix(c.Expires, 0)
	issued := time.Unix(c.Issued, 0)
	if c.Issuer != v.Issuer || !now.Before(expires) || c.Issued <= 0 || issued.After(now.Add(clockSkew)) ||
		time.Unix(c.NotBefor, 0).After(now.Add(clockSkew)) || expires.Sub(issued) > cursorMaxLifetime {
		return Session{}, ErrInvalid
	}
	// Cursor does not allowlist audiences, so a token for anyone else's
	// verifier must not work here. A Cursor-hosted run's token is refused too:
	// this broker serves only workers it can see.
	if !audienceIs(c.Audience, v.Audience) || c.Runtime != cursorRuntime || c.RunID == "" || !contains(v.TeamIDs, c.TeamID) {
		return Session{}, ErrInvalid
	}
	sum := sha256.Sum256([]byte(token))
	session := Session{Kind: KindNone, Owner: c.Subject, Run: c.RunID, Expires: expires, TokenSHA256: hex.EncodeToString(sum[:])}
	switch {
	case strings.HasPrefix(c.Subject, "service_account:") && len(c.Subject) > len("service_account:"):
		// A service account's run has no person behind it.
		session.Kind, session.Subject = KindAgent, c.Subject
	case strings.HasPrefix(c.Subject, "user:") && len(c.Subject) > len("user:"):
		if email, ok := personEmail(c.Email, v.PersonDomains); ok {
			session.Kind, session.Subject = KindPerson, email
		}
	default:
		// A projected subject (team_id:..., from sub_claim) or anything else
		// names no owner this broker can pin.
		session.Owner = ""
	}
	if !plainSubject(session.Subject) || !plainSubject(session.Owner) || !plainSubject(session.Run) {
		return Session{}, ErrInvalid
	}
	return session, nil
}

// audienceIs reports whether a string or list audience is exactly want.
func audienceIs(raw json.RawMessage, want string) bool {
	var one string
	var many []string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	return len(many) == 1 && many[0] == want
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v != "" && v == s {
			return true
		}
	}
	return false
}

// ErrUnverifiable is returned for a vendor whose verifier is not configured.
var ErrUnverifiable = errors.New("runner session verifier not configured")

// Verifiers holds the broker's session verifiers, either of which may be nil.
// Verify checks a Claude runner token and VerifyCursor a Cursor run's token,
// so a pool's profile, not the token's shape, picks the vendor.
type Verifiers struct {
	Claude *Verifier
	Cursor *CursorVerifier
}

func (s Verifiers) Verify(ctx context.Context, token string) (Session, error) {
	if s.Claude == nil {
		return Session{}, ErrUnverifiable
	}
	return s.Claude.Verify(ctx, token)
}

func (s Verifiers) VerifyCursor(ctx context.Context, token string) (Session, error) {
	if s.Cursor == nil {
		return Session{}, ErrUnverifiable
	}
	return s.Cursor.Verify(ctx, token)
}

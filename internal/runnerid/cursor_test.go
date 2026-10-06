package runnerid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type rsaIssuer struct{ keys map[string]*rsa.PrivateKey }

func (i *rsaIssuer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var keys []map[string]string
	for kid, k := range i.keys {
		keys = append(keys, map[string]string{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

// cursorClaimsFor is a token as Cursor documents it for a self-hosted run.
func cursorClaimsFor(now time.Time) map[string]any {
	return map[string]any{"iss": CursorIssuer, "sub": "user:42", "aud": "gatehouse-broker", "iat": now.Unix(),
		"nbf": now.Unix() - 5, "exp": now.Unix() + 300, "jti": "j1", "cloud_agent_id": "bc-1",
		"agent_runtime": "self_hosted", "owner_email": "alice@example.com", "owner_user_id": "42", "team_id": "7"}
}

func cursorSetup(t *testing.T) (*CursorVerifier, *rsa.PrivateKey, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(&rsaIssuer{keys: map[string]*rsa.PrivateKey{"c1": key}})
	t.Cleanup(srv.Close)
	now := time.Now()
	v := &CursorVerifier{JWKSURL: srv.URL, Issuer: CursorIssuer, Audience: "gatehouse-broker", TeamIDs: []string{"7"},
		PersonDomains: []string{"example.com"}, Client: srv.Client(), Now: func() time.Time { return now }}
	return v, key, now
}

func TestCursorPersonRun(t *testing.T) {
	v, key, now := cursorSetup(t)
	s, err := v.Verify(context.Background(), signRS256(t, key, "c1", cursorClaimsFor(now)))
	if err != nil || s.Kind != KindPerson || s.Subject != "alice@example.com" || s.Owner != "user:42" || s.Run != "bc-1" || len(s.TokenSHA256) != 64 {
		t.Fatalf("session %+v err %v", s, err)
	}
}

func TestCursorServiceAccountRunHasNoPerson(t *testing.T) {
	v, key, now := cursorSetup(t)
	c := cursorClaimsFor(now)
	c["sub"] = "service_account:9"
	s, err := v.Verify(context.Background(), signRS256(t, key, "c1", c))
	if err != nil || s.Kind != KindAgent || s.Subject != "service_account:9" || s.Owner != "service_account:9" {
		t.Fatalf("session %+v err %v", s, err)
	}
}

func TestCursorRunWithoutAMappablePerson(t *testing.T) {
	v, key, now := cursorSetup(t)
	cases := map[string]func(map[string]any){
		"no email":           func(c map[string]any) { delete(c, "owner_email") },
		"off-list domain":    func(c map[string]any) { c["owner_email"] = "alice@other.com" },
		"subdomain":          func(c map[string]any) { c["owner_email"] = "alice@sub.example.com" },
		"empty user":         func(c map[string]any) { c["sub"] = "user:" },
		"team-projected sub": func(c map[string]any) { c["sub"] = "team_id:7" },
		"no domains":         func(map[string]any) { v.PersonDomains = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v.PersonDomains = []string{"example.com"}
			c := cursorClaimsFor(now)
			change(c)
			s, err := v.Verify(context.Background(), signRS256(t, key, "c1", c))
			if err != nil || s.Kind != KindNone || s.Subject != "" {
				t.Fatalf("session %+v err %v", s, err)
			}
		})
	}
}

func TestCursorRefusals(t *testing.T) {
	v, key, now := cursorSetup(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]func(map[string]any){
		"another audience":      func(c map[string]any) { c["aud"] = "sts.amazonaws.com" },
		"audience list of two":  func(c map[string]any) { c["aud"] = []string{"gatehouse-broker", "x"} },
		"Cursor-hosted run":     func(c map[string]any) { c["agent_runtime"] = "managed" },
		"no runtime":            func(c map[string]any) { delete(c, "agent_runtime") },
		"another team":          func(c map[string]any) { c["team_id"] = "8" },
		"no team":               func(c map[string]any) { delete(c, "team_id") },
		"no run":                func(c map[string]any) { delete(c, "cloud_agent_id") },
		"another issuer":        func(c map[string]any) { c["iss"] = "https://api2.cursor.sh/cloud-agent/identity" },
		"expired":               func(c map[string]any) { c["exp"] = now.Unix() - 1 },
		"lifetime over an hour": func(c map[string]any) { c["exp"] = now.Unix() + 7200 },
		"issued in the future":  func(c map[string]any) { c["iat"] = now.Unix() + 600 },
		"subject with a quote":  func(c map[string]any) { c["sub"] = "service_account:9\"" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := cursorClaimsFor(now)
			change(c)
			if _, err := v.Verify(context.Background(), signRS256(t, key, "c1", c)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := v.Verify(context.Background(), signRS256(t, other, "c1", cursorClaimsFor(now))); err == nil {
		t.Fatal("accepted another key's signature")
	}
	// An ES256 token (a Claude runner's shape) is not a Cursor token.
	_, _, claude, n := setup(t)
	if _, err := v.Verify(context.Background(), sign(t, claude, "k1", personClaims(*n))); err == nil {
		t.Fatal("accepted an ES256 token")
	}
	for _, unset := range []func(){func() { v.TeamIDs = nil }, func() { v.Audience = "" }} {
		unset()
		if _, err := v.Verify(context.Background(), signRS256(t, key, "c1", cursorClaimsFor(now))); err == nil {
			t.Fatal("accepted without a team or audience configured")
		}
	}
}

func TestCursorJWKSRefusesWeakRSAKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the weak key under test
	srv := httptest.NewServer(&rsaIssuer{keys: map[string]*rsa.PrivateKey{"c1": small}})
	defer srv.Close()
	now := time.Now()
	v := &CursorVerifier{JWKSURL: srv.URL, Issuer: CursorIssuer, Audience: "gatehouse-broker", TeamIDs: []string{"7"},
		Client: srv.Client(), Now: func() time.Time { return now }}
	if _, err := v.Verify(context.Background(), signRS256(t, small, "c1", cursorClaimsFor(now))); err == nil {
		t.Fatal("accepted a 1024-bit key")
	}
}

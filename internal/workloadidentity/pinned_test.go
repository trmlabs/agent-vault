package workloadidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}
}

func pinnedSet(keys ...map[string]any) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

// pinnedDomain is the remote cluster's trust domain, with its public key
// pinned in configuration instead of fetched.
func pinnedDomain(rc *remoteCluster, keys ...map[string]any) TrustDomain {
	td := rc.td
	td.Keys, td.JWKSURL, td.CAFile = "pinned", "", ""
	td.JWKS = pinnedSet(keys...)
	return td
}

// A pinned domain verifies with no network call; an unknown kid and an
// expired token are refused.
func TestPinnedKeysVerifyWithoutFetching(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	r := withDomains(t, f, pinnedDomain(rc, rsaJWK(rc.kid, &rc.key.PublicKey)))
	ctx := context.Background()
	if _, d, err := r.verifyLocally(ctx, rc.token(rc.claims()), false); err != nil || d.name != "agent-sandbox" {
		t.Fatalf("valid token: %v", err)
	}
	if rc.calls.Load() != 0 {
		t.Fatalf("a pinned domain fetched keys %d times", rc.calls.Load())
	}
	rotated := &poolFixture{key: rc.key, kid: "rotated-kid"}
	if _, _, err := r.verifyLocally(ctx, rotated.token(rc.claims()), false); brokercore.DenialReason(err) != "token_keys_pinned_mismatch" {
		t.Fatalf("unknown kid: %v", err)
	}
	expired := rc.claims()
	expired.Expires = time.Now().Unix() - 1
	expired.Issued = expired.Expires - 600
	if _, _, err := r.verifyLocally(ctx, rc.token(expired), false); err == nil {
		t.Fatal("expired token admitted")
	}
	// Signed by another key under the pinned kid.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := &poolFixture{key: other, kid: rc.kid}
	if _, _, err := r.verifyLocally(ctx, forged.token(rc.claims()), false); brokercore.DenialReason(err) != "token_signature" {
		t.Fatalf("forged under a pinned kid: %v", err)
	}
}

// EC P-256 keys verify ES256 tokens, and only ES256 tokens.
func TestPinnedES256(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := map[string]any{"kty": "EC", "kid": "ec-1", "alg": "ES256", "crv": "P-256", "x": b64(ec.X.FillBytes(make([]byte, 32))), "y": b64(ec.Y.FillBytes(make([]byte, 32)))}
	r := withDomains(t, f, pinnedDomain(rc, jwk))
	sign := func(alg string, c claims) string {
		header, _ := json.Marshal(map[string]any{"alg": alg, "kid": "ec-1", "typ": "JWT"})
		payload, _ := json.Marshal(c)
		input := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(input))
		rr, ss, _ := ecdsa.Sign(rand.Reader, ec, digest[:])
		return input + "." + b64(append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
	}
	if _, _, err := r.verifyLocally(context.Background(), sign("ES256", rc.claims()), false); err != nil {
		t.Fatalf("ES256: %v", err)
	}
	if _, _, err := r.verifyLocally(context.Background(), sign("RS256", rc.claims()), false); err == nil {
		t.Fatal("an EC key verified a token naming RS256")
	}
}

// Only a complete public key set can be pinned.
func TestPinnedSetValidation(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	good := rsaJWK(rc.kid, &rc.key.PublicKey)
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the test proves a short key is refused
	for name, td := range map[string]TrustDomain{
		"private exponent d":      pinnedDomain(rc, with(map[string]any{"d": "AQAB"})),
		"private prime p":         pinnedDomain(rc, with(map[string]any{"p": "AQAB"})),
		"CRT member qi":           pinnedDomain(rc, with(map[string]any{"qi": "AQAB"})),
		"symmetric k":             pinnedDomain(rc, map[string]any{"kty": "oct", "kid": "x", "k": "AQAB"}),
		"unknown member":          pinnedDomain(rc, with(map[string]any{"x5u": "https://example.test"})),
		"empty set":               pinnedDomain(rc),
		"duplicate kid":           pinnedDomain(rc, good, good),
		"no kid":                  pinnedDomain(rc, with(map[string]any{"kid": ""})),
		"encryption key":          pinnedDomain(rc, with(map[string]any{"use": "enc"})),
		"RSA under 2048 bits":     pinnedDomain(rc, rsaJWK("small", &small.PublicKey)),
		"EC off the curve":        pinnedDomain(rc, map[string]any{"kty": "EC", "kid": "e", "crv": "P-256", "x": b64(make([]byte, 32)), "y": b64(make([]byte, 32))}),
		"pinned with a keys URL":  func() TrustDomain { td := pinnedDomain(rc, good); td.JWKSURL = rc.td.JWKSURL; return td }(),
		"pinned with a CA file":   func() TrustDomain { td := pinnedDomain(rc, good); td.CAFile = rc.td.CAFile; return td }(),
		"remote with pinned keys": func() TrustDomain { td := rc.td; td.JWKS = pinnedSet(good); return td }(),
		"not a key set":           func() TrustDomain { td := pinnedDomain(rc, good); td.JWKS = json.RawMessage(`[1]`); return td }(),
	} {
		c := f.r.config
		c.TrustDomains = []TrustDomain{td}
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Positive control.
	c := f.r.config
	c.TrustDomains = []TrustDomain{pinnedDomain(rc, good)}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("a valid pinned set refused: %v", err)
	}
}

// A shared proxy is admitted end to end under a pinned trust domain.
func TestProxyAttestedUnderPinnedKeys(t *testing.T) {
	p := setupProxy(t)
	c := p.r.config
	c.TrustDomains = []TrustDomain{pinnedDomain(p.rc, rsaJWK(p.rc.kid, &p.rc.key.PublicKey))}
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	p.r = r
	setupProfiles(p)
	if scope, err := p.r.Attest(p.ctx(t, p.a), p.rc.token(p.rc.claims()), linkIP); err != nil || scope.Pool != "sandboxes" {
		t.Fatalf("pinned proxy admission: %v %+v", err, scope)
	}
	if p.rc.calls.Load() != 0 {
		t.Fatal("a pinned domain fetched keys")
	}
}

// Each signing-key refusal has its trust-domain mode's own code and names the
// token's kid and the connection's peer, never any part of the token. A kid
// that is not a plain identifier is recorded as "invalid" plus a hash prefix.
func TestKeyRefusalsNameKidAndPeer(t *testing.T) {
	f := setupPool(t)
	ctx := context.Background()
	check := func(t *testing.T, err error, token, reason, kid string) {
		t.Helper()
		key := brokercore.DenialKey(err)
		if brokercore.DenialReason(err) != reason || key == nil || key.Peer != workerIP.String() {
			t.Fatalf("refusal %v, key %+v", err, key)
		}
		sum := sha256.Sum256([]byte(kid))
		want := brokercore.KeyDenial{Kid: kid, Peer: workerIP.String()}
		if kid == "" || len(kid) > 128 || strings.ContainsAny(kid, "\" ") {
			want.Kid, want.KidSHA256 = "invalid", hex.EncodeToString(sum[:])[:12]
		}
		if *key != want {
			t.Fatalf("key %+v, want %+v", key, want)
		}
		msg := err.Error()
		if !strings.Contains(msg, "kid="+want.Kid) || !strings.Contains(msg, "peer="+workerIP.String()) {
			t.Fatalf("error %q", msg)
		}
		for _, part := range strings.Split(token, ".") {
			if strings.Contains(msg, part) {
				t.Fatalf("error %q carries part of the token", msg)
			}
		}
	}
	// The broker's own cluster: an unknown kid has its own code.
	token := f.tokenWithKid(f.c, "unknown-kid")
	_, err := f.r.Attest(ctx, token, workerIP)
	check(t, err, token, "token_keys_in_cluster_unknown", "unknown-kid")

	rc := newRemoteCluster(t)
	r := withDomains(t, f, pinnedDomain(rc, rsaJWK(rc.kid, &rc.key.PublicKey)))
	for _, kid := range []string{"rotated-kid", `k"1`, "k 1", strings.Repeat("k", 600)} {
		token := (&poolFixture{key: rc.key, kid: kid}).token(rc.claims())
		_, err := r.Attest(ctx, token, workerIP)
		check(t, err, token, "token_keys_pinned_mismatch", kid)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	token = (&poolFixture{key: other, kid: rc.kid}).token(rc.claims())
	_, err = r.Attest(ctx, token, workerIP)
	check(t, err, token, "token_signature", rc.kid)
}

package runnerid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type issuer struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
	down bool
}

func (i *issuer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.down {
		w.WriteHeader(503)
		return
	}
	var keys []map[string]string
	for kid, k := range i.keys {
		point, _ := k.PublicKey.Bytes() // 0x04 || X || Y
		keys = append(keys, map[string]string{"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
			"x": b64(point[1:33]), "y": b64(point[33:65])})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func personClaims(now time.Time) map[string]any {
	return map[string]any{"iss": "ccr", "aud": []string{"ccpool_abc", "other"}, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(4 * time.Hour).Unix(), "ccr:role": "session_worker",
		"ccr:account_id": "user_1", "act": map[string]any{"sub": "user:user_1", "email": "Alice@Example.com"}}
}

func setup(t *testing.T) (*issuer, *Verifier, *ecdsa.PrivateKey, *time.Time) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss := &issuer{keys: map[string]*ecdsa.PrivateKey{"k1": key}}
	srv := httptest.NewServer(iss)
	t.Cleanup(srv.Close)
	now := time.Now()
	v := &Verifier{JWKSURL: srv.URL, Issuer: "ccr", PersonDomains: []string{"example.com"}, Client: srv.Client(),
		Now: func() time.Time { return now }}
	return iss, v, key, &now
}

func TestPersonSession(t *testing.T) {
	_, v, key, now := setup(t)
	s, err := v.Verify(context.Background(), sign(t, key, "k1", personClaims(*now)))
	if err != nil || s.Kind != KindPerson || s.Subject != "alice@example.com" || !s.InPool("ccpool_abc") || s.InPool("other") || len(s.TokenSHA256) != 64 {
		t.Fatalf("session %+v err %v", s, err)
	}
}

// The runner's value carries the sk-ant-cc- prefix; a hosted session's sk-ant-si- token is refused.
func TestRunnerTokenPrefix(t *testing.T) {
	_, v, key, now := setup(t)
	jwt := sign(t, key, "k1", personClaims(*now))
	s, err := v.Verify(context.Background(), "sk-ant-cc-"+jwt)
	if err != nil || s.Kind != KindPerson || s.Subject != "alice@example.com" {
		t.Fatalf("prefixed token: session %+v err %v", s, err)
	}
	bare, _ := v.Verify(context.Background(), jwt)
	if bare.TokenSHA256 == s.TokenSHA256 {
		t.Fatal("the hash must name the value the worker holds, prefix included")
	}
	for _, prefix := range []string{"sk-ant-si-", "sk-ant-"} {
		if _, err := v.Verify(context.Background(), prefix+jwt); err == nil {
			t.Fatalf("%s token accepted", prefix)
		}
	}
}

// A user session names a person only by a recorded email in a configured domain.
// attested_by is reserved and never read. Anything else: a valid session with no person.
func TestUserSessionWithoutAMappablePerson(t *testing.T) {
	for name, act := range map[string]map[string]any{
		"no email":           {"sub": "user:user_1"},
		"email off the list": {"sub": "user:user_1", "email": "alice@elsewhere.com"},
		"subdomain":          {"sub": "user:user_1", "email": "alice@mail.example.com"},
		"two at signs":       {"sub": "user:user_1", "email": "alice@evil.com@example.com"},
		"attested_by only":   {"sub": "user:user_1", "attested_by": map[string]any{"sub": "alice@example.com"}},
		"bare user id":       {"sub": "user_1", "email": "alice@example.com"},
		"empty user":         {"sub": "user:", "email": "alice@example.com"},
		"no subject at all":  {"email": "alice@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			_, v, key, now := setup(t)
			c := personClaims(*now)
			c["act"] = act
			s, err := v.Verify(context.Background(), sign(t, key, "k1", c))
			if err != nil || s.Kind != KindNone || s.Subject != "" {
				t.Fatalf("session %+v err %v", s, err)
			}
		})
	}
	t.Run("no domains configured", func(t *testing.T) {
		_, v, key, now := setup(t)
		v.PersonDomains = nil
		s, err := v.Verify(context.Background(), sign(t, key, "k1", personClaims(*now)))
		if err != nil || s.Kind != KindNone {
			t.Fatalf("session %+v err %v", s, err)
		}
	})
}

func TestAgentSessionHasNoPerson(t *testing.T) {
	_, v, key, now := setup(t)
	c := personClaims(*now)
	c["act"] = map[string]any{"sub": "agent:slack-123", "email": "alice@example.com"}
	s, err := v.Verify(context.Background(), sign(t, key, "k1", c))
	if err != nil || s.Kind != KindAgent || s.Subject != "agent:slack-123" {
		t.Fatalf("session %+v err %v", s, err)
	}
}

func TestRefusals(t *testing.T) {
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, mutate := range map[string]func(c map[string]any) (*ecdsa.PrivateKey, string){
		"forged":       func(c map[string]any) (*ecdsa.PrivateKey, string) { return other, "k1" },
		"wrong issuer": func(c map[string]any) (*ecdsa.PrivateKey, string) { c["iss"] = "evil"; return nil, "k1" },
		"wrong role":   func(c map[string]any) (*ecdsa.PrivateKey, string) { c["ccr:role"] = "admin"; return nil, "k1" },
		"expired": func(c map[string]any) (*ecdsa.PrivateKey, string) {
			c["iat"], c["exp"] = time.Now().Add(-5*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
			return nil, "k1"
		},
		"too long-lived": func(c map[string]any) (*ecdsa.PrivateKey, string) {
			c["exp"] = time.Now().Add(13 * time.Hour).Unix()
			return nil, "k1"
		},
		"no runner pool": func(c map[string]any) (*ecdsa.PrivateKey, string) { c["aud"] = "something"; return nil, "k1" },
		"unknown key":    func(c map[string]any) (*ecdsa.PrivateKey, string) { return nil, "k9" },
	} {
		t.Run(name, func(t *testing.T) {
			_, v, key, now := setup(t)
			c := personClaims(*now)
			signer, kid := mutate(c)
			if signer == nil {
				signer = key
			}
			if _, err := v.Verify(context.Background(), sign(t, signer, kid, c)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestKeyRotationAndStaleKeys(t *testing.T) {
	iss, v, key, now := setup(t)
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", personClaims(*now))); err != nil {
		t.Fatal(err)
	}
	rotated, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss.mu.Lock()
	iss.keys["k2"] = rotated
	iss.mu.Unlock()
	*now = now.Add(31 * time.Second) // past the refetch backoff
	if _, err := v.Verify(context.Background(), sign(t, rotated, "k2", personClaims(*now))); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	iss.mu.Lock()
	iss.down = true
	iss.mu.Unlock()
	*now = now.Add(2 * time.Hour) // keys older than an hour and the issuer is down
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", personClaims(*now))); err == nil {
		t.Fatal("stale keys were trusted while the JWKS was unreachable")
	}
}

// Concurrent verifies share one key fetch, a cancelled caller does not fail it,
// and redirects are refused.
func TestKeyFetchIsSharedAndRefusesRedirects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss := &issuer{keys: map[string]*ecdsa.PrivateKey{"k1": key}}
	var fetches atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/jwks", http.StatusFound)
			return
		}
		fetches.Add(1)
		<-release
		iss.ServeHTTP(w, r)
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = RefuseRedirects
	v := &Verifier{JWKSURL: srv.URL + "/jwks", Issuer: "ccr", Client: client}
	cancelled, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	results := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		ctx := context.Background()
		if i == 0 {
			ctx = cancelled // the one that starts the fetch, then gives up
		}
		wg.Add(1)
		go func() { defer wg.Done(); results <- v.key(ctx, "k1") != nil }()
		if i == 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	close(release)
	wg.Wait()
	close(results)
	ok := 0
	for r := range results {
		if r {
			ok++
		}
	}
	if fetches.Load() != 1 || ok < 4 {
		t.Fatalf("fetches %d, callers with a key %d: want one shared fetch serving the uncancelled callers", fetches.Load(), ok)
	}
	redirected := &Verifier{JWKSURL: srv.URL + "/redirect", Issuer: "ccr", Client: client}
	if redirected.key(context.Background(), "k1") != nil {
		t.Fatal("a redirected key fetch was followed")
	}
}

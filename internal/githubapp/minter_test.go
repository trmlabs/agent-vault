package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type fakeGitHub struct {
	t         *testing.T
	key       *rsa.PrivateKey
	mints     atomic.Int32
	revokes   atomic.Int32
	mu        sync.Mutex
	status    int
	extraPerm bool
	expires   time.Time
	lastBody  map[string]any
	seq       atomic.Int32
	token     func(seq int32) string // the minted token; a classic 40-character style by default
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGitHub{t: t, key: key, status: http.StatusCreated, expires: time.Now().Add(time.Hour)}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/installation/token" {
			g.revokes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/42/access_tokens" || !g.validJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		g.mints.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.lastBody = body
		if g.status != http.StatusCreated {
			w.WriteHeader(g.status)
			return
		}
		perms := body["permissions"].(map[string]any)
		if g.extraPerm {
			perms["administration"] = "write"
		}
		repo := body["repositories"].([]any)[0].(string)
		token := fmt.Sprintf("ghs_synthetictoken%04d", g.seq.Add(1))
		if g.token != nil {
			token = g.token(g.seq.Load())
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": g.expires.Format(time.RFC3339),
			"permissions": perms, "repositories": []map[string]string{{"full_name": "trmlabs/" + repo}}})
	}))
	t.Cleanup(srv.Close)
	return g, srv
}

func (g *fakeGitHub) validJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&g.key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		return false
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct{ Iat, Exp, Iss int64 }
	return json.Unmarshal(payload, &claims) == nil && claims.Iss == 7 && claims.Exp-claims.Iat <= 600 && claims.Exp > time.Now().Unix()
}

type localSigner struct{ key *rsa.PrivateKey }

func (s localSigner) SignRS256(_ context.Context, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
}

func newMinter(g *fakeGitHub, srv *httptest.Server, now *time.Time) *Minter {
	m := &Minter{Signer: localSigner{g.key}, API: srv.URL, Client: srv.Client()}
	if now != nil {
		m.Now = func() time.Time { return *now }
	}
	return m
}

var app = App{AppID: 7, InstallationID: 42}

// statelessToken is a synthetic token in GitHub's stateless installation
// format, ghs_<app id>_<JWT>: tag, then three URL-safe base64 segments joined
// by dots, n characters in all.
func statelessToken(tag string, n int) string {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = byte(i*37 + 251) // spreads across the alphabet, '-' and '_' included
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	head := tag + "_7_"
	rest := n - len(head) - 2
	if rest < 3 {
		panic("statelessToken: n too small")
	}
	a, b := rest/5, rest*2/5
	return head + body[:a] + "." + body[a:a+b] + "." + body[a+b:rest]
}

func TestTokenShape(t *testing.T) {
	for name, tc := range map[string]struct {
		token string
		ok    bool
	}{
		"classic":               {"ghs_" + strings.Repeat("A1b2", 9), true},
		"stateless 390":         {statelessToken("ghs", 390), true},
		"stateless 520":         {statelessToken("ghs", 520), true},
		"at the bound":          {statelessToken("ghs", maxTokenBytes), true},
		"over the bound":        {statelessToken("ghs", maxTokenBytes+1), false},
		"too short":             {"ghs_short", false},
		"empty":                 {"", false},
		"space":                 {"ghs_" + strings.Repeat("a", 30) + " x", false},
		"header injection":      {"ghs_" + strings.Repeat("a", 30) + "\r\nX-Injected: 1", false},
		"standard base64 plus":  {"ghs_" + strings.Repeat("a", 30) + "+", false},
		"standard base64 slash": {"ghs_" + strings.Repeat("a", 30) + "/", false},
		"base64 padding":        {"ghs_" + strings.Repeat("a", 30) + "=", false},
		"basic auth separator":  {"ghs_" + strings.Repeat("a", 30) + ":", false},
	} {
		if got := tokenShape(tc.token); got != tc.ok {
			t.Errorf("%s (%d chars): tokenShape = %v, want %v", name, len(tc.token), got, tc.ok)
		}
	}
}

func TestMinterAcceptsStatelessTokens(t *testing.T) {
	for _, n := range []int{390, 520} {
		g, srv := newFakeGitHub(t)
		g.token = func(seq int32) string { return statelessToken(fmt.Sprintf("ghs_stateless%04d", seq), n) }
		m := newMinter(g, srv, nil)
		token, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead)
		if err != nil {
			t.Fatalf("%d-character token: %v", n, err)
		}
		if want := statelessToken("ghs_stateless0001", n); token.Value() != want || len(token.Value()) != n {
			t.Fatalf("%d-character token: got %d characters, not the minted token", n, len(token.Value()))
		}
	}
}

func TestMinterRequestsOnlyOneRepoAndMinimumPermissions(t *testing.T) {
	g, srv := newFakeGitHub(t)
	m := newMinter(g, srv, nil)
	for permissions, want := range map[Permissions]map[string]any{
		ContentsRead:      {"contents": "read", "metadata": "read"},
		ContentsWrite:     {"contents": "write", "metadata": "read"},
		PullRequestsWrite: {"pull_requests": "write", "metadata": "read"},
	} {
		token, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", permissions)
		if err != nil || !strings.HasPrefix(token.Value(), "ghs_") {
			t.Fatalf("mint %+v: %v", permissions, err)
		}
		g.mu.Lock()
		body := g.lastBody
		g.mu.Unlock()
		if fmt.Sprint(body["permissions"]) != fmt.Sprint(want) || fmt.Sprint(body["repositories"]) != "[trm-b2b]" {
			t.Fatalf("requested %v", body)
		}
	}
}

func TestMinterCachesSharesAndRefreshes(t *testing.T) {
	g, srv := newFakeGitHub(t)
	now := time.Now()
	m := newMinter(g, srv, &now)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsWrite) }()
	}
	wg.Wait()
	if g.mints.Load() != 1 {
		t.Fatalf("20 concurrent requests minted %d tokens", g.mints.Load())
	}
	if _, err := m.Token(context.Background(), app, "TRMLABS/trm-b2b", ContentsRead); err != nil || g.mints.Load() != 2 {
		t.Fatal("read and write tokens must be separate")
	}
	now = now.Add(51 * time.Minute)
	g.mu.Lock()
	g.expires = now.Add(time.Hour)
	g.mu.Unlock()
	if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsWrite); err != nil || g.mints.Load() != 3 {
		t.Fatalf("token not refreshed ten minutes before expiry: mints=%d", g.mints.Load())
	}
}

func TestMinterRefusesAndRevokesAWiderToken(t *testing.T) {
	g, srv := newFakeGitHub(t)
	g.extraPerm = true
	m := newMinter(g, srv, nil)
	if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); !errors.Is(err, ErrUnavailable) || g.revokes.Load() != 1 {
		t.Fatalf("wide token: err=%v revokes=%d", err, g.revokes.Load())
	}
}

func TestMinterBacksOffAndInvalidatesSparingly(t *testing.T) {
	g, srv := newFakeGitHub(t)
	now := time.Now()
	m := newMinter(g, srv, &now)
	g.status = http.StatusInternalServerError
	for range 10 {
		if _, err := m.Token(context.Background(), app, "trmlabs/a", ContentsRead); err == nil || strings.Contains(err.Error(), "ghs_") {
			t.Fatalf("failed mint: %v", err)
		}
	}
	if g.mints.Load() != 1 {
		t.Fatalf("failures not backed off: %d mints", g.mints.Load())
	}
	g.mu.Lock()
	g.status = http.StatusCreated
	g.mu.Unlock()
	now = now.Add(failureBackoff)
	if _, err := m.Token(context.Background(), app, "trmlabs/a", ContentsRead); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		m.Invalidate(app, "trmlabs/a", ContentsRead)
		_, _ = m.Token(context.Background(), app, "trmlabs/a", ContentsRead)
	}
	if g.mints.Load() != 3 {
		t.Fatalf("50 rejections inside 30s caused %d mints, want 3", g.mints.Load())
	}
}

func TestTokenNeverPrints(t *testing.T) {
	tok := Token{value: "ghs_syntheticprint0000", Repo: "trmlabs/a"}
	for _, out := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s %q", tok, tok, tok, tok, tok)} {
		if strings.Contains(out, "ghs_") {
			t.Fatalf("token printed: %q", out)
		}
	}
}

type fakeVault struct {
	key    *rsa.PrivateKey
	pemKey string
}

func (v fakeVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{"key": v.pemKey}}}, nil
}

func (v fakeVault) WriteWithContext(_ context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	if path != "gatehouse-transit/sign/github-app/sha2-256" || data["signature_algorithm"] != "pkcs1v15" {
		return nil, errors.New("wrong transit call")
	}
	input, _ := base64.StdEncoding.DecodeString(data["input"].(string))
	digest := sha256.Sum256(input)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, v.key, crypto.SHA256, digest[:])
	return &vaultapi.Secret{Data: map[string]interface{}{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)}}, nil
}

func TestTransitAndKVSignersMintAcceptedJWTs(t *testing.T) {
	g, srv := newFakeGitHub(t)
	der := x509.MarshalPKCS1PrivateKey(g.key)
	vault := fakeVault{key: g.key, pemKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))}
	for name, signer := range map[string]JWTSigner{
		"transit": TransitSigner{Vault: vault, Mount: "gatehouse-transit", Key: "github-app"},
		"kv":      KVSigner{Vault: vault, Mount: "gatehouse", Path: "github-app", Field: "key"},
	} {
		m := &Minter{Signer: signer, API: srv.URL, Client: srv.Client()}
		if _, err := m.Token(context.Background(), app, "trmlabs/"+name, ContentsRead); err != nil {
			t.Fatalf("%s signer: %v", name, err)
		}
	}
}

func TestMinterRefusesUnsupportedPermissions(t *testing.T) {
	g, srv := newFakeGitHub(t)
	m := newMinter(g, srv, nil)
	for _, p := range []Permissions{{}, {Contents: "admin"}, {PullRequests: "read"}} {
		if _, err := m.Token(context.Background(), app, "trmlabs/a", p); err == nil {
			t.Fatalf("minted %+v", p)
		}
	}
	if g.mints.Load() != 0 {
		t.Fatal("GitHub called for an unsupported permission set")
	}
}

// Installation tokens live up to an hour at GitHub, so the broker revokes one
// when GitHub rejects it, when the catalog stops granting it, and when the
// broker stops.
func TestMinterRevokesTokensItNoLongerUses(t *testing.T) {
	g, srv := newFakeGitHub(t)
	m := newMinter(g, srv, nil)
	ctx := context.Background()
	revokes := func(want int32, what string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for g.revokes.Load() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := g.revokes.Load(); got != want {
			t.Fatalf("%s: %d revocations, want %d", what, got, want)
		}
	}
	if _, err := m.Token(ctx, app, "trmlabs/a", ContentsRead); err != nil {
		t.Fatal(err)
	}
	m.Invalidate(app, "trmlabs/a", ContentsRead)
	revokes(1, "rejected token")

	for _, repo := range []string{"trmlabs/a", "trmlabs/b"} {
		if _, err := m.Token(ctx, app, repo, ContentsRead); err != nil {
			t.Fatal(err)
		}
	}
	m.Prune(func(_ int64, repo string, _ Permissions) bool { return repo == "trmlabs/a" })
	revokes(2, "repository removed from the catalog")
	before := g.mints.Load()
	if _, err := m.Token(ctx, app, "trmlabs/a", ContentsRead); err != nil || g.mints.Load() != before {
		t.Fatalf("a still-granted token was dropped: %v", err)
	}

	m.RevokeAll()
	revokes(3, "broker stopping")
	if _, err := m.Token(ctx, app, "trmlabs/a", ContentsRead); err != nil || g.mints.Load() != before+1 {
		t.Fatalf("a revoked token was reused: %v", err)
	}
}

package hashicorp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

const testJWT = "header.payload.signature"

// fakeVault models the parts of Vault's token tree the broker relies on:
// parent logins with a fixed maximum, child sessions that die with their
// parent, and an outage switch that fails every request.
type fakeVault struct {
	t           *testing.T
	mu          sync.Mutex
	down        bool
	maxTTL      int
	logins      int
	children    int
	alive       map[string]bool
	parentOf    map[string]string // child accessor -> parent token
	revoked     []string          // parent tokens revoked by the broker
	failRevokes int               // revoke-self calls to fail before succeeding
	policyFrom  int               // logins numbered below this lack the child policy: 403
	missing     map[string]bool   // child policies no login holds: 403
	creates     int
	lastJWT     string
}

func newFakeVault(t *testing.T, maxTTL int) (*fakeVault, *httptest.Server) {
	f := &fakeVault{t: t, maxTTL: maxTTL, alive: map[string]bool{}, parentOf: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	token := r.Header.Get("X-Vault-Token")
	switch r.URL.Path {
	case "/v1/auth/gatehouse/login":
		body := decodeBody(f.t, r)
		if token != "" || body["role"] != "broker" {
			f.t.Error("login sent a token or wrong role")
		}
		f.lastJWT, _ = body["jwt"].(string)
		f.logins++
		parent := fmt.Sprintf("parent-%d", f.logins)
		f.alive[parent] = true
		writeJSON(w, map[string]any{"auth": map[string]any{"client_token": parent, "lease_duration": 600, "renewable": true}})
	case "/v1/auth/token/lookup-self":
		if !f.alive[token] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"explicit_max_ttl": f.maxTTL}})
	case "/v1/auth/token/renew-self":
		if !f.alive[token] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": 600, "renewable": true}})
	case "/v1/auth/token/revoke-self":
		if f.failRevokes > 0 {
			f.failRevokes--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.alive[token] = false
		f.revoked = append(f.revoked, token)
		for child, parent := range f.parentOf {
			if parent == token {
				delete(f.parentOf, child)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case "/v1/auth/token/create":
		var n int
		_, _ = fmt.Sscanf(token, "parent-%d", &n)
		body := decodeBody(f.t, r)
		policies, _ := body["policies"].([]any)
		if !f.alive[token] || n < f.policyFrom || (len(policies) == 1 && f.missing[fmt.Sprint(policies[0])]) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ttl, err := time.ParseDuration(body["ttl"].(string))
		if err != nil {
			f.t.Error("child TTL not a duration")
		}
		f.creates++
		f.children++
		accessor := fmt.Sprintf("session-%d", f.children)
		f.parentOf[accessor] = token
		writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "child-" + accessor, "accessor": accessor,
			"policies": []string{DatabaseCredentialPolicyName("database", "reader")}, "lease_duration": int(ttl / time.Second), "renewable": false}})
	case "/v1/auth/token/revoke-accessor":
		delete(f.parentOf, decodeBody(f.t, r)["accessor"].(string))
		w.WriteHeader(http.StatusNoContent)
	case "/v1/database/creds/reader":
		writeJSON(w, map[string]any{"lease_id": "database/creds/reader/x", "lease_duration": 1800, "renewable": true,
			"data": map[string]any{"username": "u", "password": "synthetic"}})
	default:
		f.t.Error("unexpected API path", r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeVault) snapshot() (logins, creates int, revoked []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.creates, append([]string(nil), f.revoked...)
}

func (f *fakeVault) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func (f *fakeVault) parent(accessor string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.parentOf[accessor]
}

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type jwtHarness struct {
	t     *testing.T
	vault *fakeVault
	clock *manualClock
	c     *Client
	jwt   string
}

func newJWTHarness(t *testing.T, maxTTL int, opts reauthOptions) *jwtHarness {
	t.Helper()
	vault, srv := newFakeVault(t, maxTTL)
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte(testJWT+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	api.ClearToken()
	env := map[string]string{"VAULT_JWT_MOUNT": "gatehouse", "VAULT_JWT_ROLE": "broker", "VAULT_JWT_TOKEN_FILE": jwtFile}
	clock := &manualClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	opts.tick = time.Hour // ticks are driven by the test
	c, err := newJWTClient(context.Background(), api, slog.New(slog.NewTextHandler(io.Discard, nil)), func(k string) string { return env[k] }, opts, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &jwtHarness{t: t, vault: vault, clock: clock, c: c, jwt: jwtFile}
}

// advance moves time in one-minute steps with a refresh tick after each, as
// the real loop does every few seconds.
func (h *jwtHarness) advance(d time.Duration) {
	for step := time.Duration(0); step < d; step += time.Minute {
		h.clock.add(time.Minute)
		h.c.reauthTick(context.Background())
	}
}

func (h *jwtHarness) session() (*DatabaseSession, error) {
	return h.c.NewDatabaseSession(context.Background(), "database", "reader", 30*time.Minute)
}

func (h *jwtHarness) mustSession() *DatabaseSession {
	h.t.Helper()
	return h.mustSessionFor(30 * time.Minute)
}

func (h *jwtHarness) mustSessionFor(ttl time.Duration) *DatabaseSession {
	h.t.Helper()
	s, err := h.c.NewDatabaseSession(context.Background(), "database", "reader", ttl)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func TestJWTLoginRefreshKeepsOlderLoginUntilItsLastSessionEnds(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	first := h.mustSession()
	if h.vault.parent(first.Accessor) != "parent-1" {
		t.Fatal("first session not under first login")
	}
	h.advance(20 * time.Minute)
	if logins, _, revoked := h.vault.snapshot(); logins != 2 || len(revoked) != 0 {
		t.Fatalf("logins=%d revoked=%v; want a refresh that keeps the older login", logins, revoked)
	}
	second := h.mustSession()
	if h.vault.parent(second.Accessor) != "parent-2" {
		t.Fatal("new session not under the newest login")
	}
	if h.vault.parent(first.Accessor) != "parent-1" {
		t.Fatal("refresh ended a live session")
	}
	if err := h.c.RevokeDatabaseSession(context.Background(), first.Accessor); err != nil {
		t.Fatal(err)
	}
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 1 || revoked[0] != "parent-1" {
		t.Fatalf("revoked=%v; the older login must be revoked when its last session ends", revoked)
	}
	if h.vault.parent(second.Accessor) != "parent-2" {
		t.Fatal("revoking the older login touched the current one")
	}
}

func TestJWTOlderLoginWithNoSessionIsRevokedAtNextTick(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.advance(20 * time.Minute)
	h.advance(time.Minute)
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 1 || revoked[0] != "parent-1" {
		t.Fatalf("revoked=%v", revoked)
	}
}

func TestJWTOlderLoginRevokeIsRetried(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.vault.mu.Lock()
	h.vault.failRevokes = 1
	h.vault.mu.Unlock()
	h.advance(21 * time.Minute) // refresh, then the older login's revoke fails
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 0 {
		t.Fatalf("revoked=%v", revoked)
	}
	h.advance(time.Minute)
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 1 || revoked[0] != "parent-1" {
		t.Fatalf("revoked=%v; a failed revoke must be retried", revoked)
	}
}

func TestJWTCloseRevokesLoginsWithoutSessions(t *testing.T) {
	h := newJWTHarness(t, 4*3600, defaultReauthOptions())
	held := h.mustSession()
	h.advance(20 * time.Minute) // parent-1 keeps its session; parent-2 is current
	h.c.Close()
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 1 || revoked[0] != "parent-2" {
		t.Fatalf("revoked=%v; want the idle current login only", revoked)
	}
	if h.vault.parent(held.Accessor) != "parent-1" {
		t.Fatal("close ended a live session")
	}
	if h.c.Ready() {
		t.Fatal("ready after close")
	}
}

func TestJWTOlderLoginCeilingStopsRefreshAndThenMinting(t *testing.T) {
	opts := defaultReauthOptions()
	opts.maxRetired = 3
	h := newJWTHarness(t, 4*3600, opts)
	// One long session per login keeps every older login in custody.
	var held []*DatabaseSession
	for i := 0; i < 4; i++ {
		held = append(held, h.mustSessionFor(3*time.Hour))
		if i < 3 {
			h.advance(20 * time.Minute)
		}
	}
	if logins, _, revoked := h.vault.snapshot(); logins != 4 || len(revoked) != 0 {
		t.Fatalf("logins=%d revoked=%v", logins, revoked)
	}
	if retired, sessions := h.c.logins.counts(); retired != 3 || sessions != 4 {
		t.Fatalf("retired=%d sessions=%d", retired, sessions)
	}
	// The next refresh is due but would hold a fourth older login: it waits.
	h.advance(20 * time.Minute)
	if logins, _, _ := h.vault.snapshot(); logins != 4 {
		t.Fatalf("logins=%d; refresh must wait at the ceiling", logins)
	}
	if retired, _ := h.c.logins.counts(); retired != 3 {
		t.Fatalf("retired=%d", retired)
	}
	// Once the current login ages out, minting stops without calling Vault.
	h.advance(3 * time.Minute)
	_, creates, _ := h.vault.snapshot()
	if _, err := h.session(); !errors.Is(err, errStaleLogin) {
		t.Fatalf("err=%v; minting must stop once the current login ages out", err)
	}
	if _, after, _ := h.vault.snapshot(); after != creates {
		t.Fatal("a refused mint still reached Vault")
	}
	// Ending the oldest login's session revokes it at once and frees a place.
	if err := h.c.RevokeDatabaseSession(context.Background(), held[0].Accessor); err != nil {
		t.Fatal(err)
	}
	if _, _, revoked := h.vault.snapshot(); len(revoked) != 1 || revoked[0] != "parent-1" {
		t.Fatalf("revoked=%v", revoked)
	}
	h.advance(time.Minute)
	if logins, _, _ := h.vault.snapshot(); logins != 5 {
		t.Fatalf("logins=%d; refresh should resume below the ceiling", logins)
	}
	if s := h.mustSession(); h.vault.parent(s.Accessor) != "parent-5" {
		t.Fatal("minting did not resume under the new login")
	}
}

func TestJWTVaultUnreachableAtRefreshFailsClosed(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	existing := h.mustSession()
	if _, err := existing.ReadCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.advance(19 * time.Minute)
	h.vault.setDown(true)
	h.advance(4 * time.Minute) // refresh due at 20 minutes fails
	h.vault.setDown(false)     // Vault is back, but no refresh has succeeded

	_, creates, revoked := h.vault.snapshot()
	if _, err := h.session(); !errors.Is(err, errStaleLogin) {
		t.Fatalf("err=%v; no new session without a fresh login", err)
	}
	if _, after, _ := h.vault.snapshot(); after != creates {
		t.Fatal("the broker, not Vault, must refuse the mint")
	}
	if len(revoked) != 0 || h.vault.parent(existing.Accessor) != "parent-1" {
		t.Fatal("the existing session must run on")
	}
	// The existing session runs to its granted expiry, then is refused.
	h.clock.add(existing.ExpiresAt.Sub(h.clock.Now()) - time.Second)
	if _, err := existing.ReadCredential(context.Background()); err != nil {
		t.Fatalf("existing session refused before expiry: %v", err)
	}
	h.clock.add(time.Second)
	if _, err := existing.ReadCredential(context.Background()); err == nil {
		t.Fatal("existing session served after expiry")
	}
	// The next successful refresh restores minting under a new login.
	h.c.reauthTick(context.Background())
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d", logins)
	}
	if s := h.mustSession(); h.vault.parent(s.Accessor) != "parent-2" {
		t.Fatal("recovered session not under the new login")
	}
}

func TestJWTRenewalOutageStopsMintingBeforeRefreshIsDue(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.vault.setDown(true)
	h.advance(8 * time.Minute) // renewal at 5 minutes fails; 3/4 of 600s passes
	h.vault.setDown(false)
	if _, err := h.session(); !errors.Is(err, errStaleLogin) {
		t.Fatalf("err=%v; a login with overdue renewal must not parent sessions", err)
	}
}

func TestJWTLoginReadsRotatedTokenFile(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	if err := os.WriteFile(h.jwt, []byte("rotated.payload.signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.advance(20 * time.Minute)
	h.vault.mu.Lock()
	defer h.vault.mu.Unlock()
	if h.vault.lastJWT != "rotated.payload.signature" {
		t.Fatal("refresh reused the first projected token")
	}
}

func TestJWTLoginShorterThanMinimumSessionLifetimeIsRefused(t *testing.T) {
	vault, srv := newFakeVault(t, 30*60)
	_ = vault
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte(testJWT), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	api.ClearToken()
	env := map[string]string{"VAULT_JWT_MOUNT": "gatehouse", "VAULT_JWT_ROLE": "broker", "VAULT_JWT_TOKEN_FILE": jwtFile}
	_, err := newJWTClient(context.Background(), api, slog.New(slog.NewTextHandler(io.Discard, nil)), func(k string) string { return env[k] }, defaultReauthOptions(), time.Now)
	if err == nil {
		t.Fatal("a 30-minute login cannot parent 35-minute sessions")
	}
	if _, _, revoked := vault.snapshot(); len(revoked) != 1 {
		t.Fatal("refused login was not revoked")
	}
}

func TestJWTLoginErrorsCarryNoTokenMaterial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"echo " + testJWT}})
	}))
	defer srv.Close()
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte(testJWT), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	_, err := jwtLogin(context.Background(), api, jwtConfig{mount: "gatehouse", role: "broker", tokenFile: jwtFile}, time.Now)
	if err == nil || err.Error() != "vault jwt login failed" {
		t.Fatalf("err=%v", err)
	}
}

func TestDetectAuthMethodJWT(t *testing.T) {
	env := map[string]string{"VAULT_JWT_ROLE": "broker", "VAULT_JWT_TOKEN_FILE": "/var/run/token"}
	method, err := DetectAuthMethod(func(k string) string { return env[k] }, nil)
	if err != nil || method != AuthJWT {
		t.Fatalf("method=%q err=%v", method, err)
	}
	if _, err := jwtConfigFromEnv(func(k string) string {
		return map[string]string{"VAULT_JWT_ROLE": "../x", "VAULT_JWT_TOKEN_FILE": "/t"}[k]
	}); err == nil {
		t.Fatal("unsafe role accepted")
	}
}

func (f *fakeVault) setPolicyFrom(n int) {
	f.mu.Lock()
	f.policyFrom = n
	f.mu.Unlock()
}

// A database the catalog added after the current login was issued: Vault
// refuses its child policy to that login. The broker logs in again once and
// the retry succeeds, with no wait for the scheduled refresh.
func TestJWTDeniedMintLogsInAgainAndRetries(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.vault.setPolicyFrom(2) // the apply landed after parent-1
	h.advance(2 * time.Minute)
	s, err := h.session()
	if err != nil {
		t.Fatal(err)
	}
	if h.vault.parent(s.Accessor) != "parent-2" {
		t.Fatal("retry not under the new login")
	}
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d", logins)
	}
	// The scheduled refresh counts from the new login.
	h.advance(15 * time.Minute)
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d; the schedule must not log in again early", logins)
	}
}

// A policy that no login holds costs at most one new login a minute, however
// many sessions ask, and each refusal says why.
func TestJWTDeniedMintLoginsAreBounded(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.vault.setPolicyFrom(1 << 30) // no login ever holds it
	h.advance(2 * time.Minute)
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.session()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "lacks this database's policy") {
			t.Fatalf("err=%v", err)
		}
	}
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d; 200 denied mints must share one new login", logins)
	}
	// The new login is young: another denial does not log in again.
	if _, err := h.session(); err == nil {
		t.Fatal("minted without the policy")
	}
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d", logins)
	}
	// A new login also lacked the policy, so it is missing, not new: no more
	// logins for it until the next scheduled one.
	h.advance(2 * time.Minute)
	_, _ = h.session()
	if logins, _, _ := h.vault.snapshot(); logins != 2 {
		t.Fatalf("logins=%d; a policy a new login lacked must wait for the schedule", logins)
	}
}

// A policy missing for an hour of minute-by-minute attempts costs at most one
// extra login per scheduled login, not one a minute.
func TestJWTMissingPolicyForAnHourStaysBounded(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	h.vault.setPolicyFrom(1 << 30)
	for range 60 {
		h.advance(time.Minute)
		if _, err := h.session(); err == nil {
			t.Fatal("minted without the policy")
		}
	}
	// Scheduled logins every 20 minutes from the newest login, each followed
	// by at most one login after a denial: well under the 60 a per-minute
	// re-login would make.
	if logins, _, _ := h.vault.snapshot(); logins > 7 {
		t.Fatalf("logins=%d in an hour with a missing policy", logins)
	}
}

// Each distinct missing policy can add one login per scheduled login, never
// one a minute: three missing for an hour stays within 1 + 3 + 3 x 3.
func TestJWTSeveralMissingPoliciesStayBounded(t *testing.T) {
	h := newJWTHarness(t, 3600, defaultReauthOptions())
	roles := []string{"orders", "ledger", "audit"}
	h.vault.mu.Lock()
	h.vault.missing = map[string]bool{}
	for _, role := range roles {
		h.vault.missing[DatabaseCredentialPolicyName("database", role)] = true
	}
	h.vault.mu.Unlock()
	for range 60 {
		h.advance(time.Minute)
		for _, role := range roles {
			if _, err := h.c.NewDatabaseSession(context.Background(), "database", role, 30*time.Minute); err == nil {
				t.Fatal("minted without the policy")
			}
		}
	}
	if logins, _, _ := h.vault.snapshot(); logins > 1+3+3*3 {
		t.Fatalf("logins=%d in an hour with three missing policies", logins)
	}
}

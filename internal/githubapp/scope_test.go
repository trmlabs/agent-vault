package githubapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// scopeGitHub is a fake GitHub for the installation scope check: the
// installation's settings, metadata-only listing tokens and its repositories.
type scopeGitHub struct {
	mu          sync.Mutex
	appID       int64
	selection   string
	permissions map[string]string
	suspended   bool
	repos       []string
	settingsErr int
	wideMint    bool
	listErr     int
	settings    int // GET /app/installations/42 calls
	listMints   int // metadata-only tokens
	repoMints   int // one-repository tokens
	revoked     []string
	pages       []string
}

func newScopeGitHub(t *testing.T) (*scopeGitHub, *Minter) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &scopeGitHub{appID: 7, selection: "selected", permissions: map[string]string{"contents": "write", "metadata": "read"},
		repos: []string{"trmlabs/trm-b2b"}}
	jwtCheck := &fakeGitHub{t: t, key: key}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
			g.revoked = append(g.revoked, bearer)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/app/installations/42" && jwtCheck.validJWT(bearer):
			g.settings++
			if g.settingsErr != 0 {
				w.WriteHeader(g.settingsErr)
				return
			}
			reply := map[string]any{"id": 42, "app_id": g.appID, "repository_selection": g.selection, "permissions": g.permissions, "suspended_at": nil}
			if g.suspended {
				reply["suspended_at"] = time.Now().Format(time.RFC3339)
			}
			_ = json.NewEncoder(w).Encode(reply)
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens" && jwtCheck.validJWT(bearer):
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			expires := time.Now().Add(time.Hour).Format(time.RFC3339)
			if len(body.Repositories) == 0 && g.listErr != 0 {
				w.WriteHeader(g.listErr)
				return
			}
			w.WriteHeader(http.StatusCreated)
			if len(body.Repositories) == 0 {
				if fmt.Sprint(body.Permissions) != "map[metadata:read]" {
					t.Errorf("listing token asked for %v", body.Permissions)
				}
				g.listMints++
				_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("ghs_listingtoken%04d", g.listMints), "expires_at": expires, "permissions": body.Permissions})
				return
			}
			g.repoMints++
			_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("ghs_repositorytoken%04d", g.repoMints), "expires_at": expires,
				"permissions": body.Permissions, "repositories": func() []map[string]string {
					out := []map[string]string{{"full_name": "trmlabs/" + body.Repositories[0]}}
					if g.wideMint {
						out = append(out, map[string]string{"full_name": "trmlabs/secret"})
					}
					return out
				}()})
		case r.Method == http.MethodGet && r.URL.Path == "/installation/repositories" && strings.HasPrefix(bearer, "ghs_listingtoken"):
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			g.pages = append(g.pages, r.URL.Query().Get("page"))
			var out []map[string]string
			for i := (page - 1) * 100; i < len(g.repos) && i < page*100; i++ {
				out = append(out, map[string]string{"full_name": g.repos[i]})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(g.repos), "repositories": out})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	m := &Minter{Signer: localSigner{key}, API: srv.URL, Client: srv.Client(),
		Scope: func(installation int64) Scope {
			if installation != 42 {
				t.Errorf("scope asked for installation %d", installation)
			}
			return Scope{Repos: []string{"trmlabs/trm-b2b", "trmlabs/docs"}}
		}}
	return g, m
}

func (g *scopeGitHub) counts() (settings, listMints, repoMints, revoked int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.settings, g.listMints, g.repoMints, len(g.revoked)
}

func TestScopeInsideCatalogMintsAndRevokesListingToken(t *testing.T) {
	g, m := newScopeGitHub(t)
	for range 3 {
		if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsWrite); err != nil {
			t.Fatal(err)
		}
	}
	settings, listMints, repoMints, revoked := g.counts()
	if settings != 1 || listMints != 1 || repoMints != 1 || revoked != 1 {
		t.Fatalf("settings=%d listMints=%d repoMints=%d revoked=%d", settings, listMints, repoMints, revoked)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked[0] != "ghs_listingtoken0001" {
		t.Fatalf("revoked %q, not the listing token", g.revoked[0])
	}
}

func TestScopeRefusesRepositoriesBeyondTheCatalog(t *testing.T) {
	for name, widen := range map[string]func(*scopeGitHub){
		"all repositories":    func(g *scopeGitHub) { g.selection = "all" },
		"unlisted repository": func(g *scopeGitHub) { g.repos = append(g.repos, "trmlabs/secret") },
		"listing unavailable": func(g *scopeGitHub) { g.listErr = http.StatusForbidden },
	} {
		t.Run(name, func(t *testing.T) {
			g, m := newScopeGitHub(t)
			var logs bytes.Buffer
			m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
			widen(g)
			if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err != ErrUnavailable {
				t.Fatalf("token minted for a wider installation: %v", err)
			}
			if _, _, repoMints, _ := g.counts(); repoMints != 0 {
				t.Fatal("a repository token was minted")
			}
			if !strings.Contains(logs.String(), `"outcome":"refuse"`) || strings.Contains(logs.String(), "ghs_") {
				t.Fatalf("log: %s", logs.String())
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.listMints != len(g.revoked) {
				t.Fatalf("listing tokens %d, revoked %d", g.listMints, len(g.revoked))
			}
		})
	}
}

// Settings wider than the catalog needs are reported once, and git keeps
// working: the broker requests only what each token needs.
func TestScopeWarnsOnWiderSettings(t *testing.T) {
	for name, widen := range map[string]func(*scopeGitHub){
		"pull requests":        func(g *scopeGitHub) { g.permissions["pull_requests"] = "write" },
		"workflows":            func(g *scopeGitHub) { g.permissions["workflows"] = "write" },
		"administration read":  func(g *scopeGitHub) { g.permissions["administration"] = "read" },
		"metadata write":       func(g *scopeGitHub) { g.permissions["metadata"] = "write" },
		"suspended":            func(g *scopeGitHub) { g.suspended = true },
		"another app":          func(g *scopeGitHub) { g.appID = 8 },
		"settings unavailable": func(g *scopeGitHub) { g.settingsErr = http.StatusInternalServerError },
	} {
		t.Run(name, func(t *testing.T) {
			g, m := newScopeGitHub(t)
			now := time.Now()
			m.Now = func() time.Time { return now }
			var logs bytes.Buffer
			m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
			widen(g)
			for range 2 {
				if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err != nil {
					t.Fatalf("a settings warning refused the token: %v", err)
				}
				now = now.Add(scopeTTL + time.Second)
			}
			if settings, _, _, _ := g.counts(); settings != 2 {
				t.Fatalf("settings checked %d times, want 2", settings)
			}
			if n := strings.Count(logs.String(), "github app installation scope"); n != 2 || strings.Contains(logs.String(), `"outcome":"refuse"`) {
				t.Fatalf("want a serving event per check and no refusal, log: %s", logs.String())
			}
		})
	}
}

func TestScopeAllowsPullRequestsOnlyWithAGitHubAPIEntry(t *testing.T) {
	g, m := newScopeGitHub(t)
	g.permissions["pull_requests"] = "write"
	m.Scope = func(int64) Scope { return Scope{Repos: []string{"trmlabs/trm-b2b"}, PullRequests: true} }
	if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", PullRequestsWrite); err != nil {
		t.Fatal(err)
	}
}

func TestScopeRechecksAfterTTLRetryAndCatalogChange(t *testing.T) {
	g, m := newScopeGitHub(t)
	now := time.Now()
	m.Now = func() time.Time { return now }
	token := func() error {
		_, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead)
		return err
	}
	if err := token(); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.selection = "all"
	g.mu.Unlock()
	now = now.Add(scopeTTL - time.Second)
	if err := token(); err != nil {
		t.Fatal("rechecked before the verdict expired")
	}
	now = now.Add(2 * time.Second)
	if err := token(); err == nil {
		t.Fatal("a widened installation still mints after the verdict expired")
	}
	g.mu.Lock()
	g.selection = "selected"
	g.mu.Unlock()
	now = now.Add(scopeRetry - time.Second)
	if err := token(); err == nil {
		t.Fatal("a refusal was retried before scopeRetry")
	}
	m.ForgetScope()
	if err := token(); err != nil {
		t.Fatalf("a catalog change did not recheck: %v", err)
	}
	if settings, _, _, _ := g.counts(); settings != 3 {
		t.Fatalf("settings checked %d times, want 3", settings)
	}
}

func TestScopeReadsEveryPageWithNoCap(t *testing.T) {
	g, m := newScopeGitHub(t)
	var want []string
	for i := range 1050 {
		want = append(want, fmt.Sprintf("trmlabs/repo-%04d", i))
	}
	g.repos = want
	m.Scope = func(int64) Scope { return Scope{Repos: append(want, "trmlabs/trm-b2b")} }
	if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err != nil {
		t.Fatalf("a large installation inside the catalog was refused: %v", err)
	}
	g.mu.Lock()
	pages := len(g.pages)
	g.mu.Unlock()
	if pages != 11 {
		t.Fatalf("read %d pages, want 11", pages)
	}

	// Unlisted repositories on the last page are found; a few are named and
	// the rest counted.
	g2, m2 := newScopeGitHub(t)
	var logs bytes.Buffer
	m2.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	g2.repos = append(append([]string(nil), want...), "trmlabs/x1", "trmlabs/x2", "trmlabs/x3", "trmlabs/x4", "trmlabs/x5", "trmlabs/x6", "trmlabs/x7")
	m2.Scope = func(int64) Scope { return Scope{Repos: append(want, "trmlabs/trm-b2b")} }
	if _, err := m2.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err == nil {
		t.Fatal("unlisted repositories on the last page were missed")
	}
	if !strings.Contains(logs.String(), "installed on trmlabs/x1, trmlabs/x2, trmlabs/x3, trmlabs/x4, trmlabs/x5 and 2 more") {
		t.Fatalf("log: %s", logs.String())
	}
}

// Warn mode reports reach beyond the catalog and keeps serving; the
// one-repository mint and the wide-token revoke still hold.
func TestWarnModeServesAndKeepsThePerTokenLimits(t *testing.T) {
	for name, widen := range map[string]func(*scopeGitHub){
		"all repositories":    func(g *scopeGitHub) { g.selection = "all" },
		"unlisted repository": func(g *scopeGitHub) { g.repos = append(g.repos, "trmlabs/secret") },
		"listing unavailable": func(g *scopeGitHub) { g.listErr = http.StatusForbidden },
	} {
		t.Run(name, func(t *testing.T) {
			g, m := newScopeGitHub(t)
			m.ScopeMode = ScopeWarn
			var logs bytes.Buffer
			m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
			widen(g)
			if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err != nil {
				t.Fatalf("warn mode refused: %v", err)
			}
			if !strings.Contains(logs.String(), `"mode":"warn","outcome":"serve"`) || strings.Contains(logs.String(), "ghs_") {
				t.Fatalf("log: %s", logs.String())
			}
		})
	}
	g, m := newScopeGitHub(t)
	m.ScopeMode = ScopeWarn
	g.wideMint = true
	if _, err := m.Token(context.Background(), app, "trmlabs/trm-b2b", ContentsRead); err == nil {
		t.Fatal("warn mode accepted a token for two repositories")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.revoked) < 2 { // the listing token and the wide token
		t.Fatalf("the wide token was not revoked: %d revocations", len(g.revoked))
	}
}

func TestScopeModeDefaultsToRefuse(t *testing.T) {
	for in, want := range map[string]ScopeMode{"": ScopeRefuse, "refuse": ScopeRefuse, "warn": ScopeWarn} {
		if got, err := ParseScopeMode(in); err != nil || got != want {
			t.Errorf("ParseScopeMode(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"Warn", "off", "allow"} {
		if _, err := ParseScopeMode(bad); err == nil {
			t.Errorf("ParseScopeMode(%q) accepted", bad)
		}
	}
}

// Concurrent callers share one check per installation, and the check runs
// outside the lock: a slow GitHub never holds the verdicts.
func TestScopeChecksOncePerInstallationOutsideTheLock(t *testing.T) {
	g, m := newScopeGitHub(t)
	release, reached := make(chan struct{}), make(chan struct{}, 1)
	slow := m.Client.Transport
	m.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/app/installations/42" {
			select {
			case reached <- struct{}{}:
			default:
			}
			<-release
		}
		return slow.RoundTrip(r)
	})}
	app := App{AppID: 7, InstallationID: 42}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.checkScope(context.Background(), app); err != nil {
				t.Errorf("check: %v", err)
			}
		}()
	}
	<-reached // the first check is talking to GitHub
	forgot := make(chan struct{})
	go func() { m.ForgetScope(); close(forgot) }()
	select {
	case <-forgot:
	case <-time.After(5 * time.Second):
		t.Fatal("the verdict lock was held across a GitHub call")
	}
	close(release)
	wg.Wait()
	// The catalog changed mid-check, so that verdict is not kept: the
	// waiting callers share exactly one fresh check.
	if settings, _, _, _ := g.counts(); settings != 2 {
		t.Fatalf("%d checks for 50 callers and one catalog change", settings)
	}
}

// An installation on all repositories is refused without listing them.
func TestScopeAllRepositoriesSkipsTheListing(t *testing.T) {
	g, m := newScopeGitHub(t)
	g.mu.Lock()
	g.selection = "all"
	g.mu.Unlock()
	if err := m.checkScope(context.Background(), App{AppID: 7, InstallationID: 42}); err == nil || !strings.Contains(err.Error(), "all repositories") {
		t.Fatalf("err %v", err)
	}
	if _, listMints, _, _ := g.counts(); listMints != 0 {
		t.Fatalf("%d listing tokens minted", listMints)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A caller that goes away mid-check does not cancel the shared check: the
// verdict is the installation's, not that caller's.
func TestScopeCheckOutlivesItsCaller(t *testing.T) {
	g, m := newScopeGitHub(t)
	release, reached := make(chan struct{}), make(chan struct{}, 1)
	slow := m.Client.Transport
	m.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/app/installations/42" {
			select {
			case reached <- struct{}{}:
			default:
			}
			<-release
		}
		return slow.RoundTrip(r)
	})}
	app := App{AppID: 7, InstallationID: 42}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- m.checkScope(ctx, app) }()
	<-reached
	cancel()
	close(release)
	<-first
	if err := m.checkScope(context.Background(), app); err != nil {
		t.Fatalf("a cancelled caller cached a refusal: %v", err)
	}
	if settings, _, _, _ := g.counts(); settings != 1 {
		t.Fatalf("%d checks", settings)
	}
}

// A check that panics still releases its waiters, with a refusal recorded.
func TestScopeCheckPanicReleasesWaiters(t *testing.T) {
	_, m := newScopeGitHub(t)
	calls := 0
	m.Scope = func(int64) Scope {
		calls++
		if calls == 1 {
			panic("scope source")
		}
		return Scope{Repos: []string{"trmlabs/trm-b2b"}}
	}
	app := App{AppID: 7, InstallationID: 42}
	func() {
		defer func() { _ = recover() }()
		_ = m.checkScope(context.Background(), app)
	}()
	done := make(chan error, 1)
	go func() { done <- m.checkScope(context.Background(), app) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no refusal recorded after a panic")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a panicked check left its installation waiting")
	}
}

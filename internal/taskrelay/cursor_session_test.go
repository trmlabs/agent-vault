package taskrelay

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdentitySocket serves Cursor's mint API on dir/<name>.sock, answering
// with status and a token ending in the mint count.
func fakeIdentitySocket(t *testing.T, dir, name string, status int, expires func() int64) *atomic.Int32 {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	var mints atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Aud string }
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tokens/oidc" || r.Header.Get("Content-Type") != "application/json" ||
			json.NewDecoder(r.Body).Decode(&body) != nil || body.Aud != "gatehouse-broker" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := mints.Add(1)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("h.p.%s%d", name, n), "expires_at": expires()})
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &mints
}

// socketDir is short: a Unix socket path must fit in about 100 bytes.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestCursorTokenIsMintedFromTheClaimSocketAndCached(t *testing.T) {
	dir := socketDir(t)
	now := time.Now()
	m := &cursorMinter{now: func() time.Time { return now }}
	mints := fakeIdentitySocket(t, dir, "bc-1", http.StatusOK, func() int64 { return now.Add(5 * time.Minute).Unix() })
	if got := m.token(dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("first: %q", got)
	}
	if got := m.token(dir, "gatehouse-broker"); got != "h.p.bc-11" || mints.Load() != 1 {
		t.Fatalf("cached: %q after %d mints", got, mints.Load())
	}
	// Within a minute of expiry the relay mints a fresh one.
	now = now.Add(4*time.Minute + time.Second)
	if got := m.token(dir, "gatehouse-broker"); got != "h.p.bc-12" || mints.Load() != 2 {
		t.Fatalf("refreshed: %q after %d mints", got, mints.Load())
	}
}

func TestCursorTokenNeedsExactlyOneClaim(t *testing.T) {
	dir := socketDir(t)
	m := &cursorMinter{now: time.Now}
	later := func() int64 { return time.Now().Add(5 * time.Minute).Unix() }
	if got := m.token(dir, "gatehouse-broker"); got != "" {
		t.Fatalf("no claim: %q", got)
	}
	if got := m.token(filepath.Join(dir, "missing"), "gatehouse-broker"); got != "" {
		t.Fatalf("no directory: %q", got)
	}
	// A regular file named like a socket is not a claim.
	if err := os.WriteFile(filepath.Join(dir, "bc-0.sock"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeIdentitySocket(t, dir, "bc-1", http.StatusOK, later)
	if got := m.token(dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("one claim: %q", got)
	}
	fakeIdentitySocket(t, dir, "bc-2", http.StatusOK, later)
	if got := (&cursorMinter{now: time.Now}).token(dir, "gatehouse-broker"); got != "" {
		t.Fatalf("two claims: %q", got)
	}
}

func TestCursorMintFailuresSendNothing(t *testing.T) {
	for name, c := range map[string]struct {
		status  int
		expires func() int64
	}{
		"refused":         {http.StatusForbidden, func() int64 { return time.Now().Add(time.Minute).Unix() }},
		"already expired": {http.StatusOK, func() int64 { return time.Now().Add(-time.Second).Unix() }},
	} {
		t.Run(name, func(t *testing.T) {
			dir := socketDir(t)
			fakeIdentitySocket(t, dir, "bc-1", c.status, c.expires)
			if got := (&cursorMinter{now: time.Now}).token(dir, "gatehouse-broker"); got != "" {
				t.Fatalf("%q", got)
			}
		})
	}
}

func TestSelfModeCursorSessionSource(t *testing.T) {
	valid := func(c *FixedConfig) {
		c.PostgresBindings[0].Upstream.SessionSocketDir = "/var/run/cursor-identity"
		c.PostgresBindings[0].Upstream.SessionAudience = "gatehouse-broker"
	}
	c := selfConfig()
	c.PostgresBindings = append([]PostgresConfig(nil), c.PostgresBindings...)
	valid(&c)
	if err := c.Validate(time.Now()); err != nil {
		t.Fatalf("valid Cursor source refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"relative directory":   func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionSocketDir = "identity" },
		"no audience":          func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionAudience = "" },
		"audience with spaces": func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionAudience = "a b" },
		"also a session file":  func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionFile = "/run/token" },
		"audience alone": func(c *FixedConfig) {
			c.PostgresBindings[0].Upstream.SessionSocketDir = ""
		},
	} {
		c := selfConfig()
		c.PostgresBindings = append([]PostgresConfig(nil), c.PostgresBindings...)
		valid(&c)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Only a sidecar in the run's own Pod may mint for it.
	paired := selfConfig()
	paired.Self = false
	paired.PostgresBindings = append([]PostgresConfig(nil), paired.PostgresBindings...)
	valid(&paired)
	if paired.Validate(time.Now()) == nil {
		t.Error("paired relay with a Cursor source accepted")
	}
}

// Each connection's session comes from the claim socket when one is configured.
func TestReadSessionMintsFromTheCursorSocket(t *testing.T) {
	dir := socketDir(t)
	fakeIdentitySocket(t, dir, "bc-9", http.StatusOK, func() int64 { return time.Now().Add(5 * time.Minute).Unix() })
	if got := readSession(UpstreamConfig{SessionSocketDir: dir, SessionAudience: "gatehouse-broker"}); got != "h.p.bc-91" {
		t.Fatalf("%q", got)
	}
}

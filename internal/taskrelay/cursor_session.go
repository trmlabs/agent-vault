package taskrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A Cursor worker started with --identity-socket serves one socket per claimed
// run, at <data dir>/identity/<run>.sock, owned by the worker's user with mode
// 0600 (Cursor, "OIDC tokens", Self-hosted workers; the path is the worker
// CLI's). The relay mints the run's token itself, at the moment it connects,
// so the agent never chooses which token is sent: with no claim there is no
// socket and no session, and a pool worker holds one claim at a time.
const (
	cursorMintTimeout = 3 * time.Second
	// Refresh this long before expiry; Cursor tokens live five minutes and
	// each run may mint 30 a minute.
	cursorRefreshBefore = time.Minute
	cursorMaxToken      = 8 << 10
)

type cursorToken struct {
	value   string
	expires time.Time
}

// cursorMinter caches each socket's current token until shortly before it
// expires, so one run mints a few times an hour however busy it is.
type cursorMinter struct {
	mu     sync.Mutex
	tokens map[string]cursorToken // by socket path and audience
	now    func() time.Time
}

var cursorTokens = &cursorMinter{now: time.Now}

// token returns the claimed run's token for audience, or "" when there is no
// single claim socket or the mint fails: the broker then sees no session.
func (m *cursorMinter) token(dir, audience string) string {
	socket := claimSocket(dir)
	if socket == "" {
		return ""
	}
	key := socket + "\x00" + audience
	now := m.now()
	m.mu.Lock()
	for k, t := range m.tokens {
		if !now.Before(t.expires) {
			delete(m.tokens, k)
		}
	}
	if t, ok := m.tokens[key]; ok && now.Before(t.expires.Add(-cursorRefreshBefore)) {
		m.mu.Unlock()
		return t.value
	}
	m.mu.Unlock()
	value, expires := mintCursorToken(socket, audience)
	if value == "" || !now.Before(expires) {
		return ""
	}
	m.mu.Lock()
	if m.tokens == nil {
		m.tokens = map[string]cursorToken{}
	}
	m.tokens[key] = cursorToken{value: value, expires: expires}
	m.mu.Unlock()
	return value
}

// claimSocket is the one socket in dir, or "".
func claimSocket(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	found := ""
	for _, e := range entries {
		if e.Type()&os.ModeSocket == 0 || !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		if found != "" {
			return "" // two claims: no way to tell whose request this is
		}
		found = filepath.Join(dir, e.Name())
	}
	return found
}

func mintCursorToken(socket, audience string) (string, time.Time) {
	client := &http.Client{Timeout: cursorMintTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true, Proxy: nil}}
	body, _ := json.Marshal(map[string]string{"aud": audience})
	resp, err := client.Post("http://cursor-agent/v1/tokens/oidc", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cursorMaxToken+1024))
	if err != nil || json.Unmarshal(raw, &out) != nil || len(out.Token) > cursorMaxToken ||
		strings.Count(out.Token, ".") != 2 || strings.ContainsAny(out.Token, " \t\r\n") {
		return "", time.Time{}
	}
	return out.Token, time.Unix(out.ExpiresAt, 0)
}

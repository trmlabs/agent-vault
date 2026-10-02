// Package githubapp mints short-lived GitHub App installation tokens scoped to
// one repository and the minimum permissions, for the broker to inject into
// git-over-HTTPS. The App's private key is held by a signer (Vault Transit by
// default) and never by a worker; tokens never appear in logs or errors.
package githubapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App identifies an installation of a GitHub App on one account.
type App struct {
	AppID          int64
	InstallationID int64
}

// JWTSigner returns an RS256 (RSASSA-PKCS1-v1_5, SHA-256) signature over
// input with the App's private key.
type JWTSigner interface {
	SignRS256(ctx context.Context, input []byte) ([]byte, error)
}

// Token is an installation token. It prints as its scope only.
type Token struct {
	value   string
	Repo    string
	Write   bool
	Expires time.Time
}

func (t Token) Value() string              { return t.value }
func (t Token) String() string             { return fmt.Sprintf("github-token(%s write=%t)", t.Repo, t.Write) }
func (t Token) GoString() string           { return t.String() }
func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.String())) }

var ErrUnavailable = errors.New("github installation token unavailable")

// Minter mints and caches tokens per (installation, repository, access). A
// token is reused until ten minutes before it expires; concurrent requests
// for one key share a single mint, and a failed mint is not retried for five
// seconds, so a broken App cannot be hammered.
type Minter struct {
	Signer JWTSigner
	API    string // default https://api.github.com
	Client *http.Client
	Now    func() time.Time

	mu          sync.Mutex
	cache       map[tokenKey]Token
	failed      map[tokenKey]time.Time
	flight      map[tokenKey]*sync.Mutex
	invalidated map[tokenKey]time.Time
}

type tokenKey struct {
	installation int64
	repo         string
	write        bool
}

const (
	refreshBefore      = 10 * time.Minute
	failureBackoff     = 5 * time.Second
	invalidateInterval = 30 * time.Second
)

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Token returns a token for repo ("owner/name") with contents read, or write
// when write is true, plus metadata read. Nothing else is ever requested.
func (m *Minter) Token(ctx context.Context, app App, repo string, write bool) (Token, error) {
	key := tokenKey{app.InstallationID, strings.ToLower(repo), write}
	m.mu.Lock()
	if m.cache == nil {
		m.cache, m.failed, m.flight, m.invalidated = map[tokenKey]Token{}, map[tokenKey]time.Time{}, map[tokenKey]*sync.Mutex{}, map[tokenKey]time.Time{}
	}
	if t, ok := m.cache[key]; ok && t.Expires.Sub(m.now()) > refreshBefore {
		m.mu.Unlock()
		return t, nil
	}
	lock, ok := m.flight[key]
	if !ok {
		lock = &sync.Mutex{}
		m.flight[key] = lock
	}
	m.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	cached, have := m.cache[key]
	failedAt, failed := m.failed[key]
	m.mu.Unlock()
	if have && cached.Expires.Sub(m.now()) > refreshBefore {
		return cached, nil
	}
	if failed && m.now().Sub(failedAt) < failureBackoff {
		return Token{}, ErrUnavailable
	}
	t, err := m.mint(ctx, app, key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.failed[key] = m.now()
		return Token{}, ErrUnavailable
	}
	delete(m.failed, key)
	m.cache[key] = t
	return t, nil
}

// Invalidate drops a cached token after GitHub rejects it, at most once per
// key every 30 seconds.
func (m *Minter) Invalidate(app App, repo string, write bool) {
	key := tokenKey{app.InstallationID, strings.ToLower(repo), write}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invalidated == nil {
		m.invalidated = map[tokenKey]time.Time{}
	}
	if last, ok := m.invalidated[key]; ok && m.now().Sub(last) < invalidateInterval {
		return
	}
	m.invalidated[key] = m.now()
	delete(m.cache, key)
}

func (m *Minter) jwt(ctx context.Context, appID int64) (string, error) {
	now := m.now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]int64{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := m.Signer.SignRS256(ctx, []byte(input))
	if err != nil || len(signature) == 0 {
		return "", ErrUnavailable
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (m *Minter) mint(ctx context.Context, app App, key tokenKey) (Token, error) {
	owner, name, ok := strings.Cut(key.repo, "/")
	if m.Signer == nil || app.AppID <= 0 || app.InstallationID <= 0 || !ok || owner == "" || name == "" {
		return Token{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	jwt, err := m.jwt(ctx, app.AppID)
	if err != nil {
		return Token{}, err
	}
	access := "read"
	if key.write {
		access = "write"
	}
	body, _ := json.Marshal(map[string]any{"repositories": []string{name}, "permissions": map[string]string{"contents": access, "metadata": "read"}})
	api := strings.TrimSuffix(m.API, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/app/installations/"+strconv.FormatInt(app.InstallationID, 10)+"/access_tokens", bytes.NewReader(body))
	if err != nil {
		return Token{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Token{}, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusCreated {
		return Token{}, ErrUnavailable
	}
	var granted struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if json.Unmarshal(data, &granted) != nil || !tokenShape(granted.Token) || !granted.ExpiresAt.After(m.now().Add(refreshBefore)) {
		return Token{}, ErrUnavailable
	}
	// Refuse a token broader than requested: more repositories or any other
	// permission. It is revoked rather than left valid.
	wide := len(granted.Repositories) != 1 || !strings.EqualFold(granted.Repositories[0].FullName, key.repo) || len(granted.Permissions) > 2 ||
		granted.Permissions["contents"] != access || (granted.Permissions["metadata"] != "" && granted.Permissions["metadata"] != "read")
	for name := range granted.Permissions {
		if name != "contents" && name != "metadata" {
			wide = true
		}
	}
	if wide {
		m.revoke(api, client, granted.Token)
		return Token{}, ErrUnavailable
	}
	return Token{value: granted.Token, Repo: key.repo, Write: key.write, Expires: granted.ExpiresAt}, nil
}

func (m *Minter) revoke(api string, client *http.Client, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, api+"/installation/token", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func tokenShape(t string) bool {
	if len(t) < 20 || len(t) > 255 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

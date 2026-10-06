package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Scope is what the catalog lets one installation's tokens reach: its
// repositories ("owner/name") and whether any entry opens pull requests.
type Scope struct {
	Repos        []string
	PullRequests bool
}

// ScopeMode is what the broker does when an installation reaches beyond the
// catalog: ScopeRefuse (the default) stops every token for it, ScopeWarn
// reports and keeps serving. Either way each token is still minted for one
// repository and the minimum permissions, and a wider token is revoked.
type ScopeMode string

const (
	ScopeRefuse ScopeMode = "refuse"
	ScopeWarn   ScopeMode = "warn"
)

// ParseScopeMode reads AGENT_VAULT_GITHUB_APP_SCOPE; empty is ScopeRefuse,
// so a deployment gets warn only by asking for it.
func ParseScopeMode(s string) (ScopeMode, error) {
	switch ScopeMode(s) {
	case "", ScopeRefuse:
		return ScopeRefuse, nil
	case ScopeWarn:
		return ScopeWarn, nil
	}
	return "", fmt.Errorf("AGENT_VAULT_GITHUB_APP_SCOPE must be refuse or warn")
}

// The installation's repositories on GitHub should stay inside the catalog,
// so an App widened in GitHub's settings is caught instead of quietly
// reaching more than Gatehouse grants. Reach (all repositories, an unlisted
// repository, or a list that cannot be read) is what ScopeMode governs. Other
// settings (permissions, suspension, another App) are only reported: the
// broker requests only what each token needs. Checked before tokens are
// handed out, at most every scopeTTL per installation, and again after a
// catalog change. Every check that finds anything logs one
// "github app installation scope" event, which monitors count.
const (
	scopeTTL   = 5 * time.Minute
	scopeRetry = 30 * time.Second
)

type scopeVerdict struct {
	err     error
	checked time.Time
}

var errScope = errors.New("github app installation is wider than the catalog")

// findings are what one check found: reach decides the verdict in refuse
// mode; settings never do.
type findings struct {
	reach, settings []string
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ForgetScope drops every installation's verdict, for a catalog change.
func (m *Minter) ForgetScope() {
	m.scopeMu.Lock()
	m.scopes = nil
	m.scopeGen++ // a check already running answers its caller but is not kept
	m.scopeMu.Unlock()
}

// checkScope reports whether tokens may be minted for the installation, from
// a recent verdict when there is one. Without a Scope function it passes; the
// broker always sets one.
func (m *Minter) checkScope(ctx context.Context, app App) error {
	if m.Scope == nil {
		return nil
	}
	// The lock guards the verdicts only. One check per installation runs at
	// a time, outside it, and its callers wait for that check alone, so a
	// slow installation never holds up another's tokens.
	m.scopeMu.Lock()
	for {
		if v, ok := m.scopes[app.InstallationID]; ok {
			ttl := scopeTTL
			if v.err != nil {
				ttl = scopeRetry
			}
			if m.now().Sub(v.checked) < ttl {
				m.scopeMu.Unlock()
				return v.err
			}
		}
		running, ok := m.scopeChecking[app.InstallationID]
		if !ok {
			break
		}
		m.scopeMu.Unlock()
		select {
		case <-running:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.scopeMu.Lock()
	}
	if m.scopeChecking == nil {
		m.scopeChecking = map[int64]chan struct{}{}
	}
	done := make(chan struct{})
	m.scopeChecking[app.InstallationID] = done
	gen := m.scopeGen
	m.scopeMu.Unlock()
	found := m.verifyScope(ctx, app, m.Scope(app.InstallationID))
	var err error
	outcome := "serve"
	if len(found.reach) > 0 && m.ScopeMode != ScopeWarn {
		err, outcome = fmt.Errorf("%w: %s", errScope, strings.Join(found.reach, "; ")), "refuse"
	}
	m.scopeMu.Lock()
	if gen == m.scopeGen {
		if m.scopes == nil {
			m.scopes = map[int64]scopeVerdict{}
		}
		m.scopes[app.InstallationID] = scopeVerdict{err: err, checked: m.now()}
	}
	delete(m.scopeChecking, app.InstallationID)
	close(done)
	m.scopeMu.Unlock()
	if m.Log != nil && (len(found.reach) > 0 || len(found.settings) > 0) {
		mode := m.ScopeMode
		if mode == "" {
			mode = ScopeRefuse
		}
		m.Log.Warn("github app installation scope",
			slog.Int64("installation", app.InstallationID),
			slog.String("mode", string(mode)),
			slog.String("outcome", outcome),
			slog.String("reach", strings.Join(found.reach, "; ")),
			slog.String("settings", strings.Join(found.settings, "; ")))
	}
	return err
}

// verifyScope finds reach beyond the catalog (an installation on all
// repositories, any repository the catalog does not list, or a repository list
// that cannot be read) and settings wider than the catalog needs (a
// permission other than metadata read, contents and, only with a github-api
// entry, pull requests write; a suspension; another App's installation). A
// catalog repository the installation lacks needs no check here: its mint
// already fails.
func (m *Minter) verifyScope(ctx context.Context, app App, want Scope) findings {
	var f findings
	if m.Signer == nil || app.AppID <= 0 || app.InstallationID <= 0 {
		f.reach = append(f.reach, "repositories unreadable")
		return f
	}
	timeout := m.ScopeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	jwt, err := m.jwt(ctx, app.AppID)
	if err != nil {
		f.reach = append(f.reach, "repositories unreadable")
		return f
	}
	api, client := m.api(), m.client()
	installation := api + "/app/installations/" + strconv.FormatInt(app.InstallationID, 10)

	var settings struct {
		AppID               int64             `json:"app_id"`
		RepositorySelection string            `json:"repository_selection"`
		Permissions         map[string]string `json:"permissions"`
		SuspendedAt         *time.Time        `json:"suspended_at"`
	}
	if err := m.githubJSON(ctx, client, http.MethodGet, installation, jwt, nil, http.StatusOK, &settings); err != nil {
		f.settings = append(f.settings, "settings unreadable")
	} else {
		if settings.RepositorySelection == "all" {
			f.reach = append(f.reach, "installed on all repositories")
		}
		if settings.AppID != app.AppID {
			f.settings = append(f.settings, "belongs to another app")
		}
		if settings.SuspendedAt != nil {
			f.settings = append(f.settings, "suspended")
		}
		for _, name := range sortedKeys(settings.Permissions) {
			level := settings.Permissions[name]
			switch {
			case name == "metadata" && level == "read",
				name == "contents" && (level == "read" || level == "write"),
				name == "pull_requests" && want.PullRequests && level == "write":
			default:
				f.settings = append(f.settings, "holds "+name+" "+level)
			}
		}
	}

	if settings.RepositorySelection == "all" {
		// Already wider than any catalog: listing every repository would add
		// nothing.
		return f
	}
	// A metadata-only token for the whole installation lists its repositories,
	// and is revoked straight after.
	var listing struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	body, _ := json.Marshal(map[string]any{"permissions": map[string]string{"metadata": "read"}})
	if err := m.githubJSON(ctx, client, http.MethodPost, installation+"/access_tokens", jwt, body, http.StatusCreated, &listing); err != nil || !tokenShape(listing.Token) {
		f.reach = append(f.reach, "repositories unreadable")
		return f
	}
	defer m.revoke(api, client, listing.Token)

	allowed := map[string]bool{}
	for _, r := range want.Repos {
		allowed[strings.ToLower(r)] = true
	}
	// Every page, however many repositories the installation holds; only the
	// names outside the catalog are kept, and only a few of those are named.
	const named = 5
	var extra []string
	extraCount := 0
	for page := 1; ; page++ {
		var repos struct {
			TotalCount   int `json:"total_count"`
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		url := api + "/installation/repositories?per_page=100&page=" + strconv.Itoa(page)
		if err := m.githubJSON(ctx, client, http.MethodGet, url, listing.Token, nil, http.StatusOK, &repos); err != nil {
			f.reach = append(f.reach, "repositories unreadable")
			return f
		}
		for _, r := range repos.Repositories {
			if !allowed[strings.ToLower(r.FullName)] {
				extraCount++
				if len(extra) < named {
					extra = append(extra, r.FullName)
				}
			}
		}
		if len(repos.Repositories) < 100 || page*100 >= repos.TotalCount {
			break
		}
	}
	if extraCount > 0 {
		reason := "installed on " + strings.Join(extra, ", ")
		if extraCount > len(extra) {
			reason += fmt.Sprintf(" and %d more", extraCount-len(extra))
		}
		f.reach = append(f.reach, reason)
	}
	return f
}

// githubJSON makes one GitHub API call and decodes the reply. Any other status
// or an unreadable body is ErrUnavailable; the bearer never reaches an error.
func (m *Minter) githubJSON(ctx context.Context, client *http.Client, method, url, bearer string, body []byte, status int, into any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != status || json.Unmarshal(data, into) != nil {
		return ErrUnavailable
	}
	return nil
}

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

// The installation's repositories on GitHub must stay inside the catalog, so
// an App widened in GitHub's settings stops minting instead of quietly
// reaching more than Gatehouse grants. Its other settings (permissions,
// suspension) are reported, not enforced: the broker requests only what each
// token needs, so a wider permission is a recorded risk rather than a breach.
// Checked before tokens are handed out, at most every scopeTTL per
// installation, and again after a catalog change.
const (
	scopeTTL      = 5 * time.Minute
	scopeRetry    = 30 * time.Second
	scopeMaxPages = 10
)

type scopeVerdict struct {
	err      error
	warnings string
	checked  time.Time
}

var errScope = errors.New("github app installation is wider than the catalog")

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
	m.scopeMu.Unlock()
}

// checkScope reports whether the installation is inside the catalog, from a
// recent verdict when there is one. Without a Scope function it passes; the
// broker always sets one.
func (m *Minter) checkScope(ctx context.Context, app App) error {
	if m.Scope == nil {
		return nil
	}
	m.scopeMu.Lock()
	defer m.scopeMu.Unlock()
	if v, ok := m.scopes[app.InstallationID]; ok {
		ttl := scopeTTL
		if v.err != nil {
			ttl = scopeRetry
		}
		if m.now().Sub(v.checked) < ttl {
			return v.err
		}
	}
	warnings, err := m.verifyScope(ctx, app, m.Scope(app.InstallationID))
	if m.scopes == nil {
		m.scopes = map[int64]scopeVerdict{}
	}
	previous := m.scopes[app.InstallationID].warnings
	joined := strings.Join(warnings, "; ")
	m.scopes[app.InstallationID] = scopeVerdict{err: err, warnings: joined, checked: m.now()}
	if m.Log != nil {
		if err != nil {
			m.Log.Warn("github app installation refused", slog.Int64("installation", app.InstallationID), slog.String("reason", err.Error()))
		}
		if joined != "" && joined != previous {
			m.Log.Warn("github app installation wider than needed", slog.Int64("installation", app.InstallationID), slog.String("settings", joined))
		}
	}
	return err
}

// verifyScope refuses an installation on all repositories, or on any
// repository the catalog does not list, and when the repositories cannot be
// read. A catalog repository the installation lacks needs no check here: its
// mint already fails. Settings beyond what the catalog needs (a permission
// other than metadata read, contents and, only with a github-api entry, pull
// requests write; a suspension; another App's installation) come back as
// warnings.
func (m *Minter) verifyScope(ctx context.Context, app App, want Scope) ([]string, error) {
	if m.Signer == nil || app.AppID <= 0 || app.InstallationID <= 0 {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	jwt, err := m.jwt(ctx, app.AppID)
	if err != nil {
		return nil, err
	}
	api, client := m.api(), m.client()
	installation := api + "/app/installations/" + strconv.FormatInt(app.InstallationID, 10)

	var settings struct {
		AppID               int64             `json:"app_id"`
		RepositorySelection string            `json:"repository_selection"`
		Permissions         map[string]string `json:"permissions"`
		SuspendedAt         *time.Time        `json:"suspended_at"`
	}
	var warnings []string
	if err := m.githubJSON(ctx, client, http.MethodGet, installation, jwt, nil, http.StatusOK, &settings); err != nil {
		warnings = append(warnings, "settings unreadable")
	} else {
		if settings.RepositorySelection == "all" {
			return nil, fmt.Errorf("%w: installed on all repositories", errScope)
		}
		if settings.AppID != app.AppID {
			warnings = append(warnings, "belongs to another app")
		}
		if settings.SuspendedAt != nil {
			warnings = append(warnings, "suspended")
		}
		for _, name := range sortedKeys(settings.Permissions) {
			level := settings.Permissions[name]
			switch {
			case name == "metadata" && level == "read",
				name == "contents" && (level == "read" || level == "write"),
				name == "pull_requests" && want.PullRequests && level == "write":
			default:
				warnings = append(warnings, "holds "+name+" "+level)
			}
		}
	}

	// A metadata-only token for the whole installation lists its repositories,
	// and is revoked straight after.
	var listing struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	body, _ := json.Marshal(map[string]any{"permissions": map[string]string{"metadata": "read"}})
	if err := m.githubJSON(ctx, client, http.MethodPost, installation+"/access_tokens", jwt, body, http.StatusCreated, &listing); err != nil {
		return warnings, err
	}
	if !tokenShape(listing.Token) {
		return warnings, ErrUnavailable
	}
	defer m.revoke(api, client, listing.Token)

	allowed := map[string]bool{}
	for _, r := range want.Repos {
		allowed[strings.ToLower(r)] = true
	}
	for page := 1; ; page++ {
		if page > scopeMaxPages {
			return warnings, fmt.Errorf("%w: more than %d repositories", errScope, scopeMaxPages*100)
		}
		var repos struct {
			TotalCount   int `json:"total_count"`
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		url := api + "/installation/repositories?per_page=100&page=" + strconv.Itoa(page)
		if err := m.githubJSON(ctx, client, http.MethodGet, url, listing.Token, nil, http.StatusOK, &repos); err != nil {
			return warnings, err
		}
		for _, r := range repos.Repositories {
			if !allowed[strings.ToLower(r.FullName)] {
				return warnings, fmt.Errorf("%w: installed on %s", errScope, r.FullName)
			}
		}
		if len(repos.Repositories) < 100 || page*100 >= repos.TotalCount {
			return warnings, nil
		}
	}
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

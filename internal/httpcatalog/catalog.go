// Package httpcatalog holds the operator-owned list of HTTP destinations the
// broker may reach on a worker's behalf, and the Vault-backed keys it injects.
// A destination absent from the catalog is refused.
package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Entry is one binding: an exact host, the paths and methods allowed on it,
// where the key goes, where the key lives in Vault, and which pools may use it.
type Entry struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"` // default 443
	PathPrefixes []string `json:"pathPrefixes"`
	Methods      []string `json:"methods"`
	// Header carries the key. Scheme, when set, prefixes it ("Bearer").
	Header string `json:"header"`
	Scheme string `json:"scheme,omitempty"`
	// Placeholder is what a worker may send in Header instead of the key, so
	// SDKs that insist on a key still work. The worker may also omit Header.
	Placeholder string `json:"placeholder"`
	Key         KeyRef `json:"key"`
	// Pools are the broker agent IDs of the worker pools granted this entry.
	Pools []string `json:"pools"`
	// ForwardHeaders are extra request headers the vendor needs, such as an
	// API version. Every other caller header except a fixed safe set is dropped.
	ForwardHeaders   []string `json:"forwardHeaders,omitempty"`
	MaxRequestBytes  int64    `json:"maxRequestBytes,omitempty"`  // default 1 MiB; git 1 GiB (a push)
	MaxResponseBytes int64    `json:"maxResponseBytes,omitempty"` // default 32 MiB; git 4 GiB
	// Kind "git" makes the entry a git smart-HTTP binding, and "github-api" a
	// GitHub REST binding limited to opening pull requests and commenting on
	// them. Paths, methods and the credential are derived from the kind; the
	// key is a GitHub App installation token minted per repository.
	Kind string      `json:"kind,omitempty"`
	Git  *GitBinding `json:"git,omitempty"`
}

// GitBinding names the GitHub App installation that mints tokens and the
// repositories a pool may reach, each read-only or read-write.
type GitBinding struct {
	AppID          int64     `json:"appID"`
	InstallationID int64     `json:"installationID"`
	Repos          []GitRepo `json:"repos"`
}

// GitRepo is one repository. RefPrefixes, when set, restrict which refs a
// push may create, update or delete (for example refs/heads/cursor/).
type GitRepo struct {
	Repo        string   `json:"repo"` // owner/name
	Access      string   `json:"access"`
	RefPrefixes []string `json:"refPrefixes,omitempty"`
}

// KeyRef locates a key in a KV version 2 secret. A new KV version rotates it.
type KeyRef struct {
	Mount string `json:"mount"`
	Path  string `json:"path"`
	Field string `json:"field"`
}

type Catalog struct {
	entries []Entry
}

var (
	ErrUnlisted  = errors.New("destination not in catalog")
	ErrMethod    = errors.New("method not allowed for destination")
	ErrPool      = errors.New("pool not granted destination")
	ErrReadOnly  = errors.New("repository binding is read-only")
	repoPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	refPattern   = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)
	placeholder  = regexp.MustCompile(`^__vault_[A-Z][A-Z0-9_]*__$`)
	hostPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	kvPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

var allowedMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Headers a caller may never set, because they change routing, method,
// identity or framing. ForwardHeaders cannot name them either.
var reservedHeaders = map[string]bool{
	"Host": true, "Connection": true, "Proxy-Authorization": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Keep-Alive": true, "Content-Length": true, "Content-Encoding": true,
	"Cookie": true, "Forwarded": true, "X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true,
	"X-Http-Method-Override": true, "X-Method-Override": true, "X-Original-Url": true, "X-Rewrite-Url": true,
	"Authorization": true, "X-Api-Key": true, "Accept-Encoding": true,
}

// Load reads a catalog file, rejecting unknown fields and trailing data.
func Load(path string) (Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return Catalog{}, errors.New("cannot open HTTP catalog")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return Catalog{}, errors.New("HTTP catalog exceeds size limit or cannot be read")
	}
	return Parse(data)
}

func Parse(data []byte) (Catalog, error) {
	var file struct {
		Entries []Entry `json:"entries"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&file); err != nil {
		return Catalog{}, fmt.Errorf("invalid HTTP catalog: %w", err)
	}
	if d.More() {
		return Catalog{}, errors.New("trailing HTTP catalog data")
	}
	if len(file.Entries) == 0 {
		return Catalog{}, errors.New("HTTP catalog has no entries")
	}
	names := map[string]bool{}
	routes := map[string]string{}
	kinds := map[string]string{}
	for i := range file.Entries {
		e := &file.Entries[i]
		if err := e.normalize(); err != nil {
			return Catalog{}, fmt.Errorf("HTTP catalog entry %d: %w", i, err)
		}
		if names[e.Name] {
			return Catalog{}, fmt.Errorf("duplicate HTTP catalog entry %q", e.Name)
		}
		names[e.Name] = true
		hostKey := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if kind, ok := kinds[hostKey]; ok && kind != e.Kind {
			return Catalog{}, fmt.Errorf("host %s mixes git and header entries", hostKey)
		}
		kinds[hostKey] = e.Kind
		if e.Git != nil {
			for _, repo := range e.Git.Repos {
				route := hostKey + " " + e.Kind + " " + repo.Repo
				if other, ok := routes[route]; ok {
					return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q share repository %s", other, e.Name, repo.Repo)
				}
				routes[route] = e.Name
			}
		}
		for _, prefix := range e.PathPrefixes {
			route := fmt.Sprintf("%s:%d%s", e.Host, e.Port, prefix)
			if other, ok := routes[route]; ok {
				return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q share a route", other, e.Name)
			}
			routes[route] = e.Name
		}
	}
	return Catalog{entries: file.Entries}, nil
}

func (e *Entry) normalize() error {
	if !idPattern.MatchString(e.Name) {
		return errors.New("name must be a short identifier")
	}
	e.Host = strings.ToLower(e.Host)
	labels := strings.Split(e.Host, ".")
	if !hostPattern.MatchString(e.Host) || len(e.Host) > 253 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("host must be an exact DNS name; wildcards and IPs are not allowed")
	}
	if e.Port == 0 {
		e.Port = 443
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("invalid port")
	}
	switch e.Kind {
	case "git":
		return e.normalizeGit()
	case "github-api":
		if err := e.normalizeGit(); err != nil {
			return err
		}
		for _, r := range e.Git.Repos {
			if r.Access != "write" || len(r.RefPrefixes) > 0 {
				return fmt.Errorf("github-api repository %s must have access write (open pull requests) and no ref prefixes", r.Repo)
			}
		}
		if e.MaxRequestBytes == 1<<30 {
			e.MaxRequestBytes = 1 << 20
		}
		if e.MaxResponseBytes == 4<<30 {
			e.MaxResponseBytes = 8 << 20
		}
		if e.MaxRequestBytes > 16<<20 {
			return errors.New("github-api request limit is at most 16 MiB")
		}
		return nil
	case "":
		if e.Git != nil {
			return errors.New("git settings require kind git")
		}
	default:
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if len(e.PathPrefixes) == 0 {
		return errors.New("at least one path prefix is required")
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "/./") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q", p)
		}
	}
	if len(e.Methods) == 0 {
		return errors.New("at least one method is required")
	}
	for i, m := range e.Methods {
		e.Methods[i] = strings.ToUpper(m)
		if !allowedMethods[e.Methods[i]] {
			return fmt.Errorf("method %q not supported", m)
		}
	}
	e.Header = http.CanonicalHeaderKey(e.Header)
	if !tokenPattern.MatchString(e.Header) || (reservedHeaders[e.Header] && e.Header != "Authorization" && e.Header != "X-Api-Key") {
		return errors.New("header must be a plain header name that does not affect routing")
	}
	if e.Scheme != "" && !tokenPattern.MatchString(e.Scheme) {
		return errors.New("scheme must be a single token such as Bearer")
	}
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if !kvPattern.MatchString(e.Key.Mount) || !kvPattern.MatchString(e.Key.Path) || e.Key.Field == "" || strings.Contains(e.Key.Path, "..") {
		return errors.New("key needs a KV mount, path and field")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	for i, h := range e.ForwardHeaders {
		e.ForwardHeaders[i] = http.CanonicalHeaderKey(h)
		if !tokenPattern.MatchString(h) || reservedHeaders[e.ForwardHeaders[i]] || e.ForwardHeaders[i] == e.Header {
			return fmt.Errorf("forward header %q not allowed", h)
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 1 << 20
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 32 << 20
	}
	if e.MaxRequestBytes < 0 || e.MaxRequestBytes > 16<<20 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 1<<30 {
		return errors.New("size limits out of range")
	}
	sort.Strings(e.Methods)
	return nil
}

func (e *Entry) normalizeGit() error {
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.Placeholder != "" || e.Key != (KeyRef{}) || len(e.ForwardHeaders) > 0 {
		return errors.New("git entries derive paths, methods and credentials; leave them unset")
	}
	g := e.Git
	if g == nil || g.AppID <= 0 || g.InstallationID <= 0 || len(g.Repos) == 0 {
		return errors.New("git entries need an App ID, an installation ID and repositories")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	seen := map[string]bool{}
	for i := range g.Repos {
		r := &g.Repos[i]
		r.Repo = strings.ToLower(r.Repo)
		if !repoPattern.MatchString(r.Repo) || strings.Contains(r.Repo, "..") || strings.HasSuffix(r.Repo, ".git") || seen[r.Repo] {
			return fmt.Errorf("invalid or duplicate repository %q", r.Repo)
		}
		seen[r.Repo] = true
		if r.Access != "read" && r.Access != "write" {
			return fmt.Errorf("repository %s access must be read or write", r.Repo)
		}
		if r.Access == "read" && len(r.RefPrefixes) > 0 {
			return fmt.Errorf("repository %s is read-only; ref prefixes apply to pushes", r.Repo)
		}
		for _, prefix := range r.RefPrefixes {
			if !refPattern.MatchString(prefix) || strings.Contains(prefix, "..") || strings.Contains(prefix, "//") {
				return fmt.Errorf("invalid ref prefix %q", prefix)
			}
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 1 << 30
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 4 << 30
	}
	if e.MaxRequestBytes < 1 || e.MaxRequestBytes > 2<<30 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 8<<30 {
		return errors.New("size limits out of range")
	}
	return nil
}

// GitRequest is a matched git smart-HTTP request.
type GitRequest struct {
	Entry *Entry
	Repo  GitRepo
	Write bool // receive-pack: the push service
}

// GitMatch routes a request to a git entry. ok is false when the host has no
// git entries, so the request belongs to header entries. Only the three
// smart-HTTP endpoints exist: info/refs with exactly one service parameter,
// and POST to git-upload-pack or git-receive-pack. A push needs write access.
func (c Catalog) GitMatch(host string, port int, method, path, rawQuery, pool string) (GitRequest, bool, error) {
	host = strings.ToLower(host)
	var hostEntries []*Entry
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "git" && e.Host == host && e.Port == port {
			hostEntries = append(hostEntries, e)
		}
	}
	if len(hostEntries) == 0 {
		return GitRequest{}, false, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || len(parts) < 3 {
		return GitRequest{}, true, ErrUnlisted
	}
	repo := strings.ToLower(parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"))
	endpoint := strings.Join(parts[2:], "/")
	var write bool
	switch {
	case endpoint == "info/refs" && (rawQuery == "service=git-upload-pack" || rawQuery == "service=git-receive-pack"):
		if method != "GET" {
			return GitRequest{}, true, ErrMethod
		}
		write = rawQuery == "service=git-receive-pack"
	case (endpoint == "git-upload-pack" || endpoint == "git-receive-pack") && rawQuery == "":
		if method != "POST" {
			return GitRequest{}, true, ErrMethod
		}
		write = endpoint == "git-receive-pack"
	default:
		return GitRequest{}, true, ErrUnlisted
	}
	for _, e := range hostEntries {
		for _, r := range e.Git.Repos {
			if r.Repo != repo {
				continue
			}
			matched := GitRequest{Entry: e, Repo: r, Write: write}
			switch {
			case !contains(e.Pools, pool):
				return matched, true, ErrPool
			case write && r.Access != "write":
				return matched, true, ErrReadOnly
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

// GitHubAPIMatch routes a request to a github-api entry. ok is false when the
// host has none. Only POST to these paths exists, for a listed repository:
// /repos/{owner}/{repo}/pulls (open a pull request),
// /repos/{owner}/{repo}/issues/{n}/comments (comment on one),
// /repos/{owner}/{repo}/pulls/{n}/comments and .../comments/{id}/replies
// (review comments). Reviews, merges and everything else are unlisted.
func (c Catalog) GitHubAPIMatch(host string, port int, method, path, rawQuery, pool string) (GitRequest, bool, error) {
	host = strings.ToLower(host)
	var hostEntries []*Entry
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "github-api" && e.Host == host && e.Port == port {
			hostEntries = append(hostEntries, e)
		}
	}
	if len(hostEntries) == 0 {
		return GitRequest{}, false, nil
	}
	parts := strings.Split(path, "/")
	if rawQuery != "" || len(parts) < 5 || parts[0] != "" || parts[1] != "repos" || !githubAPIEndpoint(parts[4:]) {
		return GitRequest{}, true, ErrUnlisted
	}
	repo := strings.ToLower(parts[2] + "/" + parts[3])
	for _, e := range hostEntries {
		for _, r := range e.Git.Repos {
			if r.Repo != repo {
				continue
			}
			matched := GitRequest{Entry: e, Repo: r, Write: true}
			switch {
			case method != "POST":
				return matched, true, ErrMethod
			case !contains(e.Pools, pool):
				return matched, true, ErrPool
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

func githubAPIEndpoint(rest []string) bool {
	number := func(s string) bool {
		if s == "" || len(s) > 12 {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	switch len(rest) {
	case 1:
		return rest[0] == "pulls"
	case 3:
		return (rest[0] == "issues" || rest[0] == "pulls") && number(rest[1]) && rest[2] == "comments"
	case 5:
		return rest[0] == "pulls" && number(rest[1]) && rest[2] == "comments" && number(rest[3]) && rest[4] == "replies"
	}
	return false
}

// Match returns the entry for a request, choosing the longest path prefix
// that matches on a segment boundary. A host or path outside the catalog is
// ErrUnlisted; a listed route with another method is ErrMethod; a pool
// without the grant is ErrPool, reported only after the route matched.
func (c Catalog) Match(host string, port int, method, path, pool string) (*Entry, error) {
	host = strings.ToLower(host)
	var best *Entry
	bestLen := -1
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "" || e.Host != host || e.Port != port {
			continue
		}
		for _, prefix := range e.PathPrefixes {
			if pathWithin(path, prefix) && len(prefix) > bestLen {
				best, bestLen = e, len(prefix)
			}
		}
	}
	if best == nil {
		return nil, ErrUnlisted
	}
	if !contains(best.Methods, method) {
		return best, ErrMethod
	}
	if !contains(best.Pools, pool) {
		return best, ErrPool
	}
	return best, nil
}

// HasHost reports whether any entry names host and port, so a tunnel to an
// unlisted host can be refused before it opens.
func (c Catalog) HasHost(host string, port int) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.Host == host && e.Port == port {
			return true
		}
	}
	return false
}

// Entries returns a copy of the catalog, for wiring and diagnostics.
func (c Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

func pathWithin(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ForwardsHeader reports whether a caller header is passed upstream: a fixed
// set of content-negotiation headers plus the entry's ForwardHeaders.
func (e *Entry) ForwardsHeader(name string) bool {
	switch name = http.CanonicalHeaderKey(name); name {
	case "Accept", "Accept-Language", "Content-Type", "User-Agent":
		return true
	}
	return contains(e.ForwardHeaders, name)
}

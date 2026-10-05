// Package httpcatalog holds the operator-owned list of HTTP destinations the
// broker may reach on a worker's behalf, and the Vault-backed keys it injects.
// A destination absent from the catalog is refused.
package httpcatalog

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// Entry is one binding: an exact host, the paths and methods allowed on it,
// where the key goes, where the key lives in Vault, and which pools may use it.
type Entry struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"` // default 443
	PathPrefixes []string `json:"pathPrefixes"`
	// DeniedPaths and ReadOnlyPaths are browser-session path templates (see
	// browser_paths.go): every method is refused at or below a denied one,
	// and all but GET, HEAD and OPTIONS below a read-only one.
	DeniedPaths   []string `json:"deniedPaths,omitempty"`
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	Methods       []string `json:"methods"`
	// Header carries the key. Scheme, when set, prefixes it ("Bearer").
	Header string `json:"header"`
	Scheme string `json:"scheme,omitempty"`
	// BasicUser sends the key as an HTTP Basic user name with an empty
	// password, the way clients such as axios and curl -u encode it. The
	// header is Authorization and the scheme is Basic, so neither is set.
	BasicUser bool `json:"basicUser,omitempty"`
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
	// Kind "browser-session" lets an agent's own browser use a web app as a
	// test user; see BrowserSessionBinding.
	Kind           string                 `json:"kind,omitempty"`
	Git            *GitBinding            `json:"git,omitempty"`
	Postgres       *PostgresBinding       `json:"postgres,omitempty"`
	BrowserSession *BrowserSessionBinding `json:"browserSession,omitempty"`
	// Kind "gcp" mints a short-lived Google token per entry; see GCPBinding.
	GCP *GCPBinding `json:"gcp,omitempty"`
	// Tier is T0 (data every worker allowed on the pool may read; the default),
	// T1 (a verified person in every Requires group) or T2 (T1 with
	// time-boxed groups granted through P0). Requires lists Entra group
	// object IDs and is mandatory for T1 and T2.
	Tier     string   `json:"tier,omitempty"`
	Requires []string `json:"requires,omitempty"`
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
	entries   []Entry
	pools     []Pool
	harnesses []Harness
}

// Pool names a set of workers by their Kubernetes identity. When a catalog
// defines pools, every entry may grant only defined pool names.
type Pool struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	// Identity says who can stand behind a request: "none" (Cursor; the
	// default), "claude-session" (a runner session token naming the person)
	// or "workload" (CI and automation: Entitlements, never a person).
	Identity string `json:"identity,omitempty"`
	// Ceiling is the highest tier the pool may reach (default T0). "external"
	// is below T0: the pool's workers may reach nothing, and no entry may
	// grant it, until entries can be scoped to a tenant.
	Ceiling string `json:"ceiling,omitempty"`
	// CCPoolID is the runner pool a claude-session token must be issued for.
	CCPoolID string `json:"ccpoolID,omitempty"`
	// BaseGroup gates session start in the runner's spawn hook.
	BaseGroup string `json:"baseGroup,omitempty"`
	// Entitlements are a workload pool's fixed groups.
	Entitlements []string `json:"entitlements,omitempty"`

	harness *Harness // the declared profile naming this pool, if any
}

// Pool returns the defined pool with this name.
func (c Catalog) Pool(name string) (Pool, bool) {
	for _, p := range c.pools {
		if p.Name == name {
			return p, true
		}
	}
	return Pool{}, false
}

// PostgresBinding is a database the broker reaches with a Vault dynamic role.
type PostgresBinding struct {
	Database string `json:"database"`
	Mount    string `json:"mount"`
	Role     string `json:"role"`
	SSLMode  string `json:"sslmode,omitempty"`  // default verify-full
	MaxConns int    `json:"maxConns,omitempty"` // 0: the broker's default budget
	// Access is "read" (the default) or "write", and must be "write" exactly
	// when the role is a -readwrite role.
	Access string `json:"access,omitempty"`
}

// Current lets a fixed Catalog stand wherever a live, reloading one can.
func (c Catalog) Current() Catalog { return c }

// Pools returns the defined pools.
func (c Catalog) Pools() []Pool { return append([]Pool(nil), c.pools...) }

var (
	ErrUnlisted  = errors.New("destination not in catalog")
	ErrMethod    = errors.New("method not allowed for destination")
	ErrPool      = errors.New("pool not granted destination")
	ErrReadOnly  = errors.New("repository binding is read-only")
	repoPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	refPattern   = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pgName       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)
	vaultSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	placeholder  = regexp.MustCompile(`^__vault_[A-Z][A-Z0-9_]*__$`)
	hostPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	kvPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	// The same shapes the catalog's Terraform module accepts, since these
	// strings end up in the broker's Vault policy.
	vendorKeyPath = regexp.MustCompile(`^vendors(/[a-z0-9][a-z0-9_-]*)+$`)
	vaultMount    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)
)

// ValidMount reports whether a Vault mount path has the policy-safe shape
// the catalog and broker settings share: lower-case segments, at most 127
// characters.
func ValidMount(mount string) bool { return len(mount) <= 127 && vaultMount.MatchString(mount) }

// Environment, when set (AGENT_VAULT_CATALOG_ENVIRONMENT, such as staging),
// requires every database role to be that environment's named role:
// <env>.<region>.<cluster>.<name>-readonly or -readwrite.
var Environment atomic.Value // string

func environment() string {
	env, _ := Environment.Load().(string)
	return env
}

// rolesWithoutEnvironment keeps the plain role rule when no environment is
// set. Only the e2e build (whose Kind fixture role is "readonly") and this
// package's tests set it; anywhere else an unset environment refuses every
// database entry, so the role rule cannot be skipped by leaving it out.
var rolesWithoutEnvironment bool

func validRole(role string) bool {
	env := environment()
	if env == "" {
		return rolesWithoutEnvironment && vaultSegment.MatchString(role)
	}
	pattern := `^` + regexp.QuoteMeta(env) + `\.[a-z]+\.[a-z0-9]+\.[a-z0-9-]+-(readonly|readwrite)$`
	return regexp.MustCompile(pattern).MatchString(role)
}

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
		Harnesses []Harness `json:"harnesses,omitempty"`
		Pools     []Pool    `json:"pools,omitempty"`
		Entries   []Entry   `json:"entries"`
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
	poolNames := map[string]bool{}
	pools := map[string]Pool{}
	for _, pool := range file.Pools {
		if !idPattern.MatchString(pool.Name) || poolNames[pool.Name] || !dnsLabel.MatchString(pool.Namespace) || !dnsLabel.MatchString(pool.ServiceAccount) {
			return Catalog{}, fmt.Errorf("invalid or duplicate pool %q", pool.Name)
		}
		if err := pool.validate(); err != nil {
			return Catalog{}, fmt.Errorf("pool %q: %w", pool.Name, err)
		}
		poolNames[pool.Name] = true
		pools[pool.Name] = pool
	}
	profiles, err := validateHarnesses(file.Harnesses, pools)
	if err != nil {
		return Catalog{}, err
	}
	for i := range file.Pools {
		if h, ok := profiles[file.Pools[i].Name]; ok {
			file.Pools[i].harness = &h
		}
	}
	names := map[string]bool{}
	users := map[KVRef]string{}
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
		if err := e.validateTier(); err != nil {
			return Catalog{}, fmt.Errorf("HTTP catalog entry %q: %w", e.Name, err)
		}
		for _, pool := range e.Pools {
			if len(poolNames) > 0 && !poolNames[pool] {
				return Catalog{}, fmt.Errorf("HTTP catalog entry %q grants undefined pool %q", e.Name, pool)
			}
			if err := grantable(*e, pools[pool], len(poolNames) > 0); err != nil {
				return Catalog{}, fmt.Errorf("HTTP catalog entry %q to pool %q: %w", e.Name, pool, err)
			}
		}
		hostKey := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if kind, ok := kinds[hostKey]; ok && (kind != e.Kind || e.Kind == "browser-session") {
			return Catalog{}, fmt.Errorf("host %s mixes entry kinds or repeats a browser-session host", hostKey)
		}
		kinds[hostKey] = e.Kind
		if e.BrowserSession != nil {
			// A test user signs in for one entry only, so its session and
			// audit trail belong to that entry's pool.
			if other, ok := users[e.BrowserSession.User]; ok {
				return Catalog{}, fmt.Errorf("browser-session entries %q and %q share a test user", other, e.Name)
			}
			users[e.BrowserSession.User] = e.Name
			// The app host belongs to its entry alone.
			appKey := fmt.Sprintf("%s:%d", e.BrowserSession.AppHost, e.Port)
			if _, ok := kinds[appKey]; ok {
				return Catalog{}, fmt.Errorf("browser app host %s is already in the catalog", appKey)
			}
			kinds[appKey] = "browser-session-app"
		}
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
	return Catalog{entries: file.Entries, pools: file.Pools, harnesses: file.Harnesses}, nil
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
		if e.Kind == "postgres" {
			e.Port = 5432
		}
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("invalid port")
	}
	if e.Kind != "browser-session" && (len(e.DeniedPaths) > 0 || len(e.ReadOnlyPaths) > 0) {
		return errors.New("deniedPaths and readOnlyPaths apply to browser-session entries only")
	}
	switch e.Kind {
	case "postgres":
		return e.normalizePostgres()
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
	case "browser-session":
		return e.normalizeBrowser()
	case "gcp":
		return e.normalizeGCP()
	case "":
		if e.Git != nil || e.Postgres != nil || e.BrowserSession != nil || e.GCP != nil {
			return errors.New("git, postgres, browserSession or gcp settings require their kind")
		}
	default:
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if len(e.PathPrefixes) == 0 {
		return errors.New("at least one path prefix is required")
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\;") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "/./") || strings.Contains(p, "__") {
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
	if e.BasicUser && (e.Header != "Authorization" || e.Scheme != "") {
		return errors.New("basicUser needs header Authorization and no scheme")
	}
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if !ValidMount(e.Key.Mount) || len(e.Key.Path) > 127 || !vendorKeyPath.MatchString(e.Key.Path) || e.Key.Field == "" {
		return errors.New("key needs a KV mount, a path under vendors/ and a field")
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

func (e *Entry) normalizePostgres() error {
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.BasicUser || e.Placeholder != "" || e.Key != (KeyRef{}) ||
		len(e.ForwardHeaders) > 0 || e.Git != nil || e.BrowserSession != nil || e.GCP != nil || e.MaxRequestBytes != 0 || e.MaxResponseBytes != 0 {
		return errors.New("postgres entries take only host, port, pools and postgres settings")
	}
	p := e.Postgres
	if environment() == "" && !rolesWithoutEnvironment {
		return errors.New("database entries need AGENT_VAULT_CATALOG_ENVIRONMENT (or validate --environment), which names their roles")
	}
	if p == nil || !pgName.MatchString(p.Database) || !validRole(p.Role) {
		return errors.New("postgres entries need a database name and a Vault role")
	}
	if !ValidMount(p.Mount) {
		return errors.New("invalid Vault database mount")
	}
	writes := strings.HasSuffix(p.Role, "-readwrite")
	switch {
	case p.Access == "":
		p.Access = "read"
	case p.Access != "read" && p.Access != "write":
		return fmt.Errorf("access %q: read or write", p.Access)
	}
	if (p.Access == "write") != writes {
		return errors.New("access is write exactly when the role is a -readwrite role")
	}
	// Modes that skip the certificate check let anyone on the network path
	// relay SCRAM and hold a session as the minted user.
	switch {
	case p.SSLMode == "":
		p.SSLMode = "verify-full"
	case p.SSLMode == "verify-full":
	case p.SSLMode == "disable" && plaintextDatabases.Load() && clusterLocal(e.Host):
	default:
		return fmt.Errorf("sslmode %q: catalog databases use verify-full", p.SSLMode)
	}
	if p.MaxConns < 0 || p.MaxConns > 1000 {
		return errors.New("maxConns out of range")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	return nil
}

// Database returns the postgres entry a pool asks for by name. An unknown
// name is ErrUnlisted; a pool without the grant is ErrPool.
func (c Catalog) Database(name, pool string) (*Entry, error) {
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "postgres" || e.Name != name {
			continue
		}
		if !contains(e.Pools, pool) {
			return e, ErrPool
		}
		return e, nil
	}
	return nil, ErrUnlisted
}

// CheckHosts requires every host to end with one of suffixes (for example
// ".crunchybridge.com"), so CI can hold the catalog inside the ranges the
// broker's network policy allows.
func (c Catalog) CheckHosts(suffixes []string) error {
	for _, e := range c.entries {
		ok := false
		for _, suffix := range suffixes {
			suffix = strings.ToLower(strings.TrimSpace(suffix))
			if suffix != "" && (e.Host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(e.Host, "."+strings.TrimPrefix(suffix, "."))) {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("entry %q host %s is outside the allowed domains", e.Name, e.Host)
		}
	}
	return nil
}

func (e *Entry) normalizeGit() error {
	if e.Postgres != nil || e.BrowserSession != nil || e.GCP != nil {
		return errors.New("postgres settings require kind postgres")
	}
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.BasicUser || e.Placeholder != "" || e.Key != (KeyRef{}) || len(e.ForwardHeaders) > 0 {
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
		if e.Kind != "postgres" && e.Host == host && e.Port == port {
			return true
		}
		if e.BrowserSession != nil && e.BrowserSession.AppHost == host && e.Port == port {
			return true
		}
	}
	return false
}

// HasAuth0Domain reports whether host is the Auth0 domain of a
// browser-session entry: the only hosts the broker's own logins may reach.
func (c Catalog) HasAuth0Domain(host string) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.Auth0.Domain == host {
			return true
		}
	}
	return false
}

// HasAutomatedAuth reports whether addr (host:port) is the automated-auth
// service of a browser-session entry: the only other place the broker's own
// logins may reach.
func (c Catalog) HasAutomatedAuth(addr string) bool {
	addr = strings.ToLower(addr)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.AutomatedAuth != nil && e.BrowserSession.AutomatedAuth.Addr() == addr {
			return true
		}
	}
	return false
}

// Entries returns a copy of the catalog, for wiring and diagnostics.
func (c Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// GitGranted reports whether some entry still lets the installation's tokens
// reach repo at a scope: "contents-read" (a git entry), "contents-write" (a git
// entry with write access) or "pull-requests" (a github-api entry).
func (c Catalog) GitGranted(installation int64, repo, scope string) bool {
	for _, e := range c.entries {
		if e.Git == nil || e.Git.InstallationID != installation {
			continue
		}
		for _, r := range e.Git.Repos {
			if !strings.EqualFold(r.Repo, repo) {
				continue
			}
			switch {
			case e.Kind == "git" && scope == "contents-read",
				e.Kind == "git" && scope == "contents-write" && r.Access == "write",
				e.Kind == "github-api" && scope == "pull-requests":
				return true
			}
		}
	}
	return false
}

// clusterLocal reports whether host is a Kubernetes Service name, the only
// kind of host a plaintext database entry may name.
func clusterLocal(host string) bool {
	return strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".svc")
}

// plaintextDatabases lets a database entry for a Kubernetes Service host use
// sslmode disable, and an automated-auth service on one use plain http. Only a binary built with the e2e tag can set it (see
// plaintext_e2e.go), for the Kind fixture database, which serves no TLS.
var plaintextDatabases atomic.Bool

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

var (
	groupID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ccpoolID = regexp.MustCompile(`^ccpool_[A-Za-z0-9]{1,120}$`)
	tierRank = map[string]int{"": 0, "T0": 0, "T1": 1, "T2": 2}
)

// CeilingExternal is the ceiling below T0, for workers serving people
// outside the company.
const CeilingExternal = "external"

func (p Pool) validate() error {
	if p.Ceiling == CeilingExternal {
		if p.Identity != "" && p.Identity != "none" {
			return fmt.Errorf("an external pool has no verified identity")
		}
	} else if _, ok := tierRank[p.Ceiling]; !ok {
		return fmt.Errorf("unknown ceiling %q", p.Ceiling)
	}
	for _, g := range append(append([]string(nil), p.Entitlements...), p.BaseGroup) {
		if g != "" && !groupID.MatchString(g) {
			return fmt.Errorf("groups must be Entra object IDs")
		}
	}
	switch p.Identity {
	case "", "none":
		if p.CCPoolID != "" || len(p.Entitlements) != 0 || p.BaseGroup != "" || tierRank[p.Ceiling] > 0 {
			return fmt.Errorf("a pool with no verified identity reaches T0 only and takes no runner or workload settings")
		}
	case "claude-session":
		if !ccpoolID.MatchString(p.CCPoolID) || len(p.Entitlements) != 0 {
			return fmt.Errorf("a claude-session pool needs its ccpool_ ID and takes no fixed entitlements")
		}
	case "workload":
		if p.CCPoolID != "" || p.BaseGroup != "" || tierRank[p.Ceiling] > 1 {
			return fmt.Errorf("a workload pool takes fixed entitlements only and never reaches T2")
		}
	default:
		return fmt.Errorf("unknown identity %q", p.Identity)
	}
	return nil
}

func (e *Entry) validateTier() error {
	rank, ok := tierRank[e.Tier]
	if !ok {
		return fmt.Errorf("unknown tier %q", e.Tier)
	}
	if rank == 0 && len(e.Requires) != 0 {
		return fmt.Errorf("a T0 entry requires no groups")
	}
	if rank > 0 && len(e.Requires) == 0 {
		return fmt.Errorf("a %s entry must name its required groups", e.Tier)
	}
	// The audit row records the groups checked within its 512-byte identifier
	// limit; more groups would make every request on the entry fail closed.
	if len(e.Requires) > maxRequiredGroups {
		return fmt.Errorf("an entry requires at most %d groups", maxRequiredGroups)
	}
	for _, g := range e.Requires {
		if !groupID.MatchString(g) {
			return fmt.Errorf("required groups must be Entra object IDs")
		}
	}
	return nil
}

const maxRequiredGroups = 8

// grantable is the CI rule: an entry above T0 is never granted to a pool that
// cannot carry it. Without defined pools only T0 entries may be granted.
func grantable(e Entry, p Pool, defined bool) error {
	if p.Ceiling == CeilingExternal {
		return fmt.Errorf("a pool at the external ceiling holds no entries")
	}
	rank := tierRank[e.Tier]
	if rank == 0 {
		return nil
	}
	if !defined {
		return fmt.Errorf("%s entries need defined pools", e.Tier)
	}
	if rank > tierRank[p.Ceiling] {
		return fmt.Errorf("%s exceeds the pool's ceiling", e.Tier)
	}
	switch p.Identity {
	case "claude-session":
		return nil
	case "workload":
		if rank >= 2 {
			return fmt.Errorf("T2 is never granted to a workload pool")
		}
		have := map[string]bool{}
		for _, g := range p.Entitlements {
			have[g] = true
		}
		for _, g := range e.Requires {
			if !have[g] {
				return fmt.Errorf("the workload pool lacks a required group")
			}
		}
		return nil
	}
	return fmt.Errorf("%s entries are never granted to a pool with no verified identity", e.Tier)
}

// Credential is the header value that carries v: v after Scheme, or for a
// Basic user, "Basic " and the base64 of v and an empty password.
func (e *Entry) Credential(v string) string {
	switch {
	case e.BasicUser:
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(v+":"))
	case e.Scheme != "":
		return e.Scheme + " " + v
	}
	return v
}

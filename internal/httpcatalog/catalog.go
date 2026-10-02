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
	MaxRequestBytes  int64    `json:"maxRequestBytes,omitempty"`  // default 1 MiB
	MaxResponseBytes int64    `json:"maxResponseBytes,omitempty"` // default 32 MiB
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
	for i := range file.Entries {
		e := &file.Entries[i]
		if err := e.normalize(); err != nil {
			return Catalog{}, fmt.Errorf("HTTP catalog entry %d: %w", i, err)
		}
		if names[e.Name] {
			return Catalog{}, fmt.Errorf("duplicate HTTP catalog entry %q", e.Name)
		}
		names[e.Name] = true
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
		if e.Host != host || e.Port != port {
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

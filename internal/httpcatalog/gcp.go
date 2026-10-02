package httpcatalog

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// GCPBinding mints a short-lived Google access token per entry, in one of two
// ways, and the broker adds it as Authorization on the entry's host and paths.
//
// Downscope (Bucket set): a Credential Access Boundary on the broker's own
// identity, limited to one bucket, one object prefix and one storage role.
// Google supports these for Cloud Storage only.
//
// Impersonate (ServiceAccount set): a token for a dedicated service account
// that holds only this entry's role, such as one BigQuery dataset. The broker
// may mint tokens for exactly the service accounts the catalog names: its
// TokenCreator grant is on each of them, never on a project.
type GCPBinding struct {
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Role   string `json:"role,omitempty"`

	ServiceAccount string   `json:"serviceAccount,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`

	// LifetimeSeconds bounds how long a minted token is used. Default 900,
	// at most 3600. A downscoped token also ends with the broker's own token.
	LifetimeSeconds int `json:"lifetimeSeconds,omitempty"`
}

var (
	gcsBucket      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$`)
	gcsPrefix      = regexp.MustCompile(`^([A-Za-z0-9_-]+/)+$`)
	serviceAccount = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	googleScope    = regexp.MustCompile(`^https://www\.googleapis\.com/auth/[a-z0-9._-]+$`)
	// Storage roles a boundary may carry: object data only, never bucket or IAM administration.
	storageRoles = map[string]bool{"roles/storage.objectViewer": true, "roles/storage.objectCreator": true, "roles/storage.objectUser": true}
	// Hosts that mint or manage credentials are never a destination.
	mintingHosts = map[string]bool{"sts.googleapis.com": true, "iamcredentials.googleapis.com": true, "oauth2.googleapis.com": true,
		"iam.googleapis.com": true, "accounts.google.com": true, "www.googleapis.com": true}
)

// gcpForwardHeaders are the request headers Google clients need, besides an
// entry's ForwardHeaders.
var gcpForwardHeaders = []string{"Accept", "Content-Type", "User-Agent", "X-Goog-Api-Client", "X-Goog-User-Project",
	"X-Upload-Content-Type", "X-Upload-Content-Length", "Content-Range", "Range", "If-Match", "If-None-Match"}

func (e *Entry) normalizeGCP() error {
	if e.Git != nil || e.Postgres != nil || e.BrowserSession != nil || e.Key != (KeyRef{}) || e.Header != "" || e.Scheme != "" {
		return errors.New("gcp entries take host, pools, placeholder, tier, gcp and optional paths, methods and forward headers")
	}
	g := e.GCP
	if g == nil {
		return errors.New("gcp entries need gcp settings")
	}
	if !strings.HasSuffix(e.Host, ".googleapis.com") || mintingHosts[e.Host] {
		return errors.New("gcp entries reach a googleapis.com service, never one that mints or manages credentials")
	}
	// Cloud data: never T0, so never granted to a pool without a person behind it.
	if e.Tier != "T1" && e.Tier != "T2" {
		return errors.New("gcp entries are tier T1 or T2")
	}
	switch {
	case g.Bucket != "" && g.ServiceAccount == "":
		if e.Host != "storage.googleapis.com" || !gcsBucket.MatchString(g.Bucket) || !gcsPrefix.MatchString(g.Prefix) ||
			strings.Contains(g.Bucket, "..") || !storageRoles[g.Role] || len(g.Scopes) > 0 {
			return errors.New("a downscoped entry needs storage.googleapis.com, a bucket, a prefix ending in / and an object role")
		}
		if len(e.PathPrefixes) == 0 {
			e.PathPrefixes = []string{"/storage/v1/b/" + g.Bucket + "/", "/upload/storage/v1/b/" + g.Bucket + "/", "/download/storage/v1/b/" + g.Bucket + "/"}
		}
	case g.ServiceAccount != "" && g.Bucket == "":
		if !serviceAccount.MatchString(g.ServiceAccount) || g.Prefix != "" || g.Role != "" || len(e.PathPrefixes) == 0 {
			return errors.New("an impersonating entry needs a service account email and explicit path prefixes")
		}
		if len(g.Scopes) == 0 {
			g.Scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
		}
		for _, s := range g.Scopes {
			if !googleScope.MatchString(s) {
				return fmt.Errorf("invalid scope %q", s)
			}
		}
	default:
		return errors.New("gcp entries set either bucket (downscope) or serviceAccount (impersonate)")
	}
	if g.LifetimeSeconds == 0 {
		g.LifetimeSeconds = 900
	}
	if g.LifetimeSeconds < 300 || g.LifetimeSeconds > 3600 {
		return errors.New("gcp lifetimeSeconds must be 300 to 3600")
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q", p)
		}
	}
	if len(e.Methods) == 0 {
		e.Methods = []string{"DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"}
	}
	for i, m := range e.Methods {
		e.Methods[i] = strings.ToUpper(m)
		if !allowedMethods[e.Methods[i]] {
			return fmt.Errorf("method %q not supported", m)
		}
	}
	sort.Strings(e.Methods)
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
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
		if !tokenPattern.MatchString(h) || reservedHeaders[e.ForwardHeaders[i]] {
			return fmt.Errorf("forward header %q not allowed", h)
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 16 << 20
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 256 << 20
	}
	if e.MaxRequestBytes < 0 || e.MaxRequestBytes > 1<<30 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 4<<30 {
		return errors.New("size limits out of range")
	}
	return nil
}

// GCPMatch routes a request to a gcp entry by the longest path prefix. ok is
// false when no gcp entry names the host.
func (c Catalog) GCPMatch(host string, port int, method, path, pool string) (*Entry, bool, error) {
	host = strings.ToLower(host)
	var best *Entry
	bestLen, listed := -1, false
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "gcp" || e.Host != host || e.Port != port {
			continue
		}
		listed = true
		for _, prefix := range e.PathPrefixes {
			if pathWithin(path, prefix) && len(prefix) > bestLen {
				best, bestLen = e, len(prefix)
			}
		}
	}
	switch {
	case !listed:
		return nil, false, nil
	case best == nil:
		return nil, true, ErrUnlisted
	case !contains(best.Methods, method):
		return best, true, ErrMethod
	case !contains(best.Pools, pool):
		return best, true, ErrPool
	}
	return best, true, nil
}

// GCPForwardsHeader reports whether a caller header passes to Google.
func (e *Entry) GCPForwardsHeader(name string) bool {
	name = http.CanonicalHeaderKey(name)
	return contains(gcpForwardHeaders, name) || contains(e.ForwardHeaders, name)
}

package httpcatalog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A browser-session entry signs its test user in to the whole API it names,
// and the test user is often an admin of its organization. The path guard
// keeps a worker from using that session to mint a credential of its own or
// to change the account: such a credential would outlive the session and
// would not look like the token the response screen catches.
//
// deniedSegments are refused anywhere in an API path, in any case and with
// "-" and "_" ignored, so /organizations/1/apiKey, /v1/API_KEYS and
// /users/change-password all match.
var deniedSegments = segmentSet("apikey", "apikeys", "password", "changepassword", "resetpassword", "mfa", "otp", "totp",
	"invitations", "invites", "oauth", "tokens", "token", "sso", "saml", "scim", "connections", "roles", "ipallowlist",
	"authentication", "admin", "usermanagement", "bulkoperations", "rotatesecret", "webhooks", "credentials", "secrets",
	"keys", "clientsecret", "permissions", "impersonate", "sessions")

// readOnlySegments pass only GET, HEAD and OPTIONS wherever they appear: the
// app reads them at start-up, and the same routes invite and create users.
var readOnlySegments = segmentSet("usersorganizations")

func segmentSet(names ...string) map[string]bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return set
}

// foldSegment is a path segment as the segment sets hold it.
func foldSegment(s string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(s))
}

var (
	ErrDeniedPath   = errors.New("path denied for browser sessions")
	ErrReadOnlyPath = errors.New("path is read-only for browser sessions")
)

// templateSegment is one segment of a deniedPaths or readOnlyPaths template:
// a name, or * for any one segment.
var templateSegment = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._~-]{0,127})$`)

func pathSegments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// templateCovers reports whether a path lies at or below a template, with *
// matching any one segment. Names compare without case: the guard fails
// closed on an API that routes case-insensitively.
func templateCovers(template, path []string) bool {
	if len(path) < len(template) {
		return false
	}
	for i, t := range template {
		if t != "*" && !strings.EqualFold(t, path[i]) {
			return false
		}
	}
	return true
}

func (e *Entry) normalizeBrowserPaths() error {
	// No default: an entry names the parts of the API its workers need.
	if len(e.PathPrefixes) == 0 {
		return errors.New("browser-session entries list their pathPrefixes")
	}
	templates := map[string][][]string{}
	for field, list := range map[string][]string{"deniedPaths": e.DeniedPaths, "readOnlyPaths": e.ReadOnlyPaths} {
		for _, t := range list {
			segments := pathSegments(t)
			valid := strings.HasPrefix(t, "/") && !strings.HasSuffix(t, "/") && !strings.Contains(t, "//") && len(segments) > 0
			for _, s := range segments {
				valid = valid && templateSegment.MatchString(s) && s != "." && s != ".."
			}
			if !valid {
				return fmt.Errorf("invalid %s template %q", field, t)
			}
			templates[field] = append(templates[field], segments)
		}
	}
	for _, p := range e.PathPrefixes {
		segments := pathSegments(p)
		if !strings.HasPrefix(p, "/") || len(segments) == 0 || strings.ContainsAny(p, "?#%*{} \\;") || strings.Contains(p, "//") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q: browser-session prefixes name a part of the API, never /", p)
		}
		for _, s := range segments {
			if s == "." || s == ".." {
				return fmt.Errorf("invalid path prefix %q", p)
			}
			if deniedSegments[foldSegment(s)] {
				return fmt.Errorf("path prefix %q contains a denied segment", p)
			}
		}
		// A prefix at or below a denied template grants nothing; one above
		// it grants the rest of its branch, and the template is refused at
		// run time.
		for _, t := range templates["deniedPaths"] {
			if templateCovers(t, segments) {
				return fmt.Errorf("path prefix %q lies within deniedPaths template /%s", p, strings.Join(t, "/"))
			}
		}
	}
	return nil
}

// guardBrowserPath applies the path guard to a request for the API host.
func (e *Entry) guardBrowserPath(method, path string) error {
	segments := pathSegments(path)
	readOnly := false
	for _, s := range segments {
		folded := foldSegment(s)
		if deniedSegments[folded] {
			return ErrDeniedPath
		}
		readOnly = readOnly || readOnlySegments[folded]
	}
	for _, t := range e.DeniedPaths {
		if templateCovers(pathSegments(t), segments) {
			return ErrDeniedPath
		}
	}
	for _, t := range e.ReadOnlyPaths {
		readOnly = readOnly || templateCovers(pathSegments(t), segments)
	}
	if readOnly && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return ErrReadOnlyPath
	}
	return nil
}

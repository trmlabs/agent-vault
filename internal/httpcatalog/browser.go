package httpcatalog

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// BrowserSessionBinding lets an agent's own browser use a web app as a test
// user without holding the user's password or any token. The browser loads
// the app from AppHost with no credential. It calls the app's API (the
// entry's Host) with a placeholder access token, which the broker replaces
// with a real one minted for the test user. A login seed from the broker puts
// the placeholder, and an unsigned ID token carrying the user's non-secret
// claims, where the app's Auth0 client looks for them.
type BrowserSessionBinding struct {
	AppHost string       `json:"appHost"`
	Auth0   Auth0Binding `json:"auth0"`
	// User is a KV version 2 secret with fields email and password.
	User KVRef `json:"user"`
}

// Auth0Binding describes the app's Auth0 client and how the broker logs in.
type Auth0Binding struct {
	Domain   string `json:"domain"`
	ClientID string `json:"clientID"` // the app's public client: names the browser cache entries
	Audience string `json:"audience"`
	// Scope is what the app's client requests; the browser cache key uses it.
	// Default "openid profile email offline_access" (auth0-spa-js with refresh
	// tokens). The broker's own login drops offline_access.
	Scope string `json:"scope,omitempty"`
	Realm string `json:"realm"` // database connection holding the test user
	// TokenClient is a KV version 2 secret with fields client_id and
	// client_secret: a confidential client allowed the password-realm grant.
	TokenClient KVRef `json:"tokenClient"`
}

// KVRef is a KV version 2 secret whose fields the binding names.
type KVRef struct {
	Mount string `json:"mount"`
	Path  string `json:"path"`
}

// Field locates one field of the secret.
func (r KVRef) Field(name string) KeyRef { return KeyRef{Mount: r.Mount, Path: r.Path, Field: name} }

// BrowserSeedPath is answered by the broker on the API host and never
// forwarded: it returns the login seed for the agent's browser.
const BrowserSeedPath = "/.gatehouse/browser-seed"

// BrowserRequest is a request routed to a browser-session entry: to the API
// host, to the app host, or for the seed.
type BrowserRequest struct {
	Entry *Entry
	App   bool // the app's own host: no credential
	Seed  bool
}

// The API takes every method a browser sends, including CORS preflight.
var browserMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}

// BrowserForwardHeaders are the browser request headers passed upstream,
// besides an entry's ForwardHeaders. Cookies never pass: the app keeps its
// session in the Authorization header, and a cookie is a credential.
var BrowserForwardHeaders = []string{"Accept", "Accept-Language", "Access-Control-Request-Headers", "Access-Control-Request-Method",
	"Cache-Control", "Content-Type", "If-Modified-Since", "If-None-Match", "Origin", "Pragma", "Referer", "User-Agent"}

func (e *Entry) normalizeBrowser() error {
	if e.Git != nil || e.Postgres != nil || e.GCP != nil || e.Key != (KeyRef{}) || e.Header != "" || e.Scheme != "" || len(e.Methods) > 0 {
		return errors.New("browser-session entries take host, pools, placeholder, browserSession and optional path prefixes and forward headers")
	}
	b := e.BrowserSession
	if b == nil {
		return errors.New("browser-session entries need browserSession settings")
	}
	b.AppHost = strings.ToLower(b.AppHost)
	if !hostPattern.MatchString(b.AppHost) || b.AppHost == e.Host {
		return errors.New("browserSession.appHost must be an exact DNS name other than the API host")
	}
	a := &b.Auth0
	a.Domain = strings.ToLower(a.Domain)
	if !hostPattern.MatchString(a.Domain) || !idPattern.MatchString(a.ClientID) || a.Audience == "" || len(a.Audience) > 256 ||
		strings.ContainsAny(a.Audience, " \t\r\n") || !idPattern.MatchString(a.Realm) {
		return errors.New("browserSession.auth0 needs a domain, client ID, audience and realm")
	}
	if a.Scope == "" {
		a.Scope = "openid profile email offline_access"
	}
	if len(a.Scope) > 256 || !strings.Contains(" "+a.Scope+" ", " openid ") || !printableASCII(a.Scope) {
		return errors.New("browserSession.auth0.scope must include openid")
	}
	for _, ref := range []KVRef{b.User, a.TokenClient} {
		if !kvPattern.MatchString(ref.Mount) || !kvPattern.MatchString(ref.Path) || strings.Contains(ref.Path, "..") {
			return errors.New("browserSession user and tokenClient need a KV mount and path")
		}
	}
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if len(e.PathPrefixes) == 0 {
		e.PathPrefixes = []string{"/"}
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q", p)
		}
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
		e.MaxRequestBytes = 1 << 20
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 32 << 20
	}
	if e.MaxRequestBytes < 0 || e.MaxRequestBytes > 16<<20 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 1<<30 {
		return errors.New("size limits out of range")
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// BrowserMatch routes a request to a browser-session entry. ok is false when
// neither the API host nor the app host of any such entry matches. The app
// host serves GET and HEAD only.
func (c Catalog) BrowserMatch(host string, port int, method, path, pool string) (BrowserRequest, bool, error) {
	host = strings.ToLower(host)
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "browser-session" || port != e.Port {
			continue
		}
		switch host {
		case e.BrowserSession.AppHost:
			matched := BrowserRequest{Entry: e, App: true}
			switch {
			case method != "GET" && method != "HEAD":
				return matched, true, ErrMethod
			case !contains(e.Pools, pool):
				return matched, true, ErrPool
			}
			return matched, true, nil
		case e.Host:
			matched := BrowserRequest{Entry: e, Seed: path == BrowserSeedPath}
			within := matched.Seed
			for _, prefix := range e.PathPrefixes {
				within = within || pathWithin(path, prefix)
			}
			switch {
			case !within:
				return matched, true, ErrUnlisted
			case !browserMethods[method] || (matched.Seed && method != "GET"):
				return matched, true, ErrMethod
			case !contains(e.Pools, pool):
				return matched, true, ErrPool
			}
			return matched, true, nil
		}
	}
	return BrowserRequest{}, false, nil
}

package httpcatalog

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	// AutomatedAuth names TRM's automated-auth service when Auth0.Login is
	// "automated-auth".
	AutomatedAuth *AutomatedAuthBinding `json:"automatedAuth,omitempty"`
}

// AutomatedAuthBinding names TRM's automated-auth service, the login profile
// it holds for the app, and the Auth0 organization the user signs in to.
type AutomatedAuthBinding struct {
	// URL is the service's https base URL: an exact DNS name, no path.
	URL     string `json:"url"`
	Profile string `json:"profile"`
	OrgID   string `json:"orgID"`
	// Key is a KV version 2 secret with field private_key, the service's
	// caller key.
	Key KVRef `json:"key"`
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
	// Login is how the broker signs the user in: "password-realm" (the
	// default), Auth0's password-realm grant through TokenClient, or
	// "automated-auth", Universal Login through TRM's automated-auth service.
	// Only the second can sign in to an Auth0 organization: Auth0 refuses the
	// password-realm grant for organization-enabled applications.
	Login string `json:"login,omitempty"`
	Realm string `json:"realm,omitempty"` // database connection holding the test user
	// TokenClient is a KV version 2 secret with fields client_id and
	// client_secret: a confidential client allowed the password-realm grant.
	TokenClient KVRef `json:"tokenClient,omitempty"`
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
	if e.Git != nil || e.Postgres != nil || e.GCP != nil || e.Key != (KeyRef{}) || e.Header != "" || e.Scheme != "" || e.BasicUser || len(e.Methods) > 0 {
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
		strings.ContainsAny(a.Audience, " \t\r\n") {
		return errors.New("browserSession.auth0 needs a domain, client ID and audience")
	}
	if a.Scope == "" {
		a.Scope = "openid profile email offline_access"
	}
	if len(a.Scope) > 256 || !strings.Contains(" "+a.Scope+" ", " openid ") || !printableASCII(a.Scope) {
		return errors.New("browserSession.auth0.scope must include openid")
	}
	refs := []KVRef{b.User, a.TokenClient}
	switch a.Login {
	case "", "password-realm":
		a.Login = "password-realm"
		if b.AutomatedAuth != nil || !idPattern.MatchString(a.Realm) {
			return errors.New("browserSession.auth0 login password-realm needs a realm and tokenClient, and no automatedAuth")
		}
	case "automated-auth":
		// A realm is unused here and harmless; a token client would be a
		// second sign-in secret with nothing to use it.
		if b.AutomatedAuth == nil || a.TokenClient != (KVRef{}) {
			return errors.New("browserSession.auth0 login automated-auth needs automatedAuth, and no tokenClient")
		}
		if err := b.AutomatedAuth.normalize(); err != nil {
			return err
		}
		refs = []KVRef{b.User, b.AutomatedAuth.Key}
	default:
		return errors.New("browserSession.auth0.login must be password-realm or automated-auth")
	}
	for _, ref := range refs {
		if !kvPattern.MatchString(ref.Mount) || !kvPattern.MatchString(ref.Path) || strings.Contains(ref.Path, "..") {
			return errors.New("browserSession user and login secrets need a KV mount and path")
		}
	}
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if err := e.normalizeBrowserPaths(); err != nil {
		return err
	}
	// The test user is one account: one pool's workers share it, and no
	// other entry may sign in as it (see Parse).
	if len(e.Pools) != 1 {
		return errors.New("a browser-session entry grants exactly one pool")
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

func (s *AutomatedAuthBinding) normalize() error {
	u, err := url.Parse(s.URL)
	if err != nil || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("browserSession.automatedAuth.url must be a bare base URL")
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil {
		return errors.New("browserSession.automatedAuth.url must name its host, not an address")
	}
	switch {
	case u.Scheme == "https" && hostPattern.MatchString(host):
	// The login carries the user's password and the service key: plain http
	// only to a Kubernetes Service, and only in an e2e build, as for databases.
	case u.Scheme == "http" && hostPattern.MatchString(host) && clusterLocal(host) && plaintextDatabases.Load():
	default:
		return errors.New("browserSession.automatedAuth.url must be https")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return errors.New("browserSession.automatedAuth.url has an invalid port")
		}
		host = net.JoinHostPort(host, p)
	}
	s.URL = u.Scheme + "://" + host
	// The org is required: a test user in several organizations would
	// otherwise sign in to whichever one the login page offers first.
	if !idPattern.MatchString(s.Profile) || !idPattern.MatchString(s.OrgID) {
		return errors.New("browserSession.automatedAuth needs a profile and an orgID")
	}
	return nil
}

// Addr is the host:port the broker dials for the service.
func (s *AutomatedAuthBinding) Addr() string {
	u, _ := url.Parse(s.URL)
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "http" {
		return net.JoinHostPort(u.Hostname(), "80")
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// BrowserHost reports whether host:port is a browser-session entry's API host
// or app host: a host whose TLS leaf the browser CA signs.
func (c Catalog) BrowserHost(host string, port int) bool {
	host = strings.ToLower(host)
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind == "browser-session" && port == e.Port && (host == e.Host || host == e.BrowserSession.AppHost) {
			return true
		}
	}
	return false
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
			case !matched.Seed:
				if err := e.guardBrowserPath(method, path); err != nil {
					return matched, true, err
				}
			}
			return matched, true, nil
		}
	}
	return BrowserRequest{}, false, nil
}

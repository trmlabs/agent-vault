package mitm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// maxSeedLife bounds the placeholder session a seed describes, for a worker
// without a deadline: the workload identity's default session ceiling. A pool
// worker's seed ends at its Pod's deadline.
const maxSeedLife = 24 * time.Hour

// forwardBrowser serves a browser-session entry: the app's own host with no
// credential, the login seed, and the API with the placeholder access token
// replaced by the test user's real one. Cookies never pass in either
// direction, and every response is screened for the real token.
func (p *Proxy) forwardBrowser(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, b httpcatalog.BrowserRequest, matchErr error) {
	a := p.adapter
	if b.Entry != nil {
		event.Binding = b.Entry.Name
		if b.App {
			event.Binding += "/app"
		}
	}
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	switch {
	case errors.Is(matchErr, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(matchErr, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case errors.Is(matchErr, httpcatalog.ErrDeniedPath):
		deny(http.StatusForbidden, "denied_path")
		return
	case errors.Is(matchErr, httpcatalog.ErrReadOnlyPath):
		deny(http.StatusForbidden, "read_only_path")
		return
	case matchErr != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	entry := b.Entry
	if a.BrowserTokens == nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	expected := hostHeaderForScheme("https", target)
	// Upgrades (WebSocket) are refused until an app needs them; the staging
	// app streams over fetch, which passes as an ordinary response.
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafeBrowserPath(r.URL.Path, b.Seed) || containsPlaceholder(r.URL.RawQuery) || r.Header.Get("Upgrade") != "" ||
		r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	credential := "Bearer " + entry.Placeholder
	if got := r.Header.Values("Authorization"); len(got) > 1 || (len(got) == 1 && (b.App || got[0] != credential)) {
		deny(http.StatusBadRequest, "credential_header")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, entry.MaxRequestBytes+1))
	switch {
	case err != nil:
		deny(http.StatusBadRequest, "request_shape")
		return
	case int64(len(body)) > entry.MaxRequestBytes:
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	case len(body) > 0 && (r.Method == http.MethodGet || r.Method == http.MethodHead || b.App):
		deny(http.StatusBadRequest, "request_shape")
		return
	case containsPlaceholder(string(body)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer enf.Release()
	token, err := a.BrowserTokens.Token(r.Context(), entry)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	admittedAt := time.Now()
	finish := func(status int, outcome string) {
		done := event
		done.Event, done.Outcome, done.Status = auditchain.EventHTTPResponse, outcome, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		_ = a.Audit.Record(done)
	}
	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if b.Seed {
		admitted.Outcome = "seed"
	}
	if err := a.Audit.Record(admitted); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if b.Seed {
		seed, err := browserSeed(entry, token, scope, time.Now())
		if err != nil {
			finish(http.StatusServiceUnavailable, "seed_unavailable")
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(seed)
		finish(http.StatusOK, "completed")
		return
	}

	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		finish(http.StatusBadRequest, "request_shape")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	out.Host = expected
	for _, name := range append(append([]string(nil), httpcatalog.BrowserForwardHeaders...), entry.ForwardHeaders...) {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), v...)
		}
	}
	real := "Bearer " + token.Value()
	if !b.App {
		out.Header.Set("Authorization", real)
	}
	out.Header.Set("Accept-Encoding", "identity")
	needles := secretRepresentations(map[string]string{"token": token.Value(), "credential": real})
	p.relayScreened(noCookieWriter{w}, out, needles, entry.MaxResponseBytes, finish, func(resp *http.Response) {
		if !b.App && invalidToken(resp) {
			a.BrowserTokens.Invalidate(entry)
		}
	}, nil)
}

// invalidToken reports whether the API refused the token itself: a 401 that
// names no error, or names invalid_token. A 403, or a 401 for another reason
// such as insufficient_scope, says nothing about the token, and a worker
// could otherwise force a fresh login per request by calling such a path.
func invalidToken(resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	for _, challenge := range resp.Header.Values("WWW-Authenticate") {
		if i := strings.Index(challenge, "error="); i >= 0 && !strings.HasPrefix(strings.Trim(challenge[i+len("error="):], `" `), "invalid_token") {
			return false
		}
	}
	return true
}

func containsPlaceholder(s string) bool { return bytes.Contains([]byte(s), []byte(placeholderMarker)) }

// unsafeBrowserPath is unsafePath, except that the seed path's own name is
// allowed.
func unsafeBrowserPath(path string, seed bool) bool {
	if seed {
		return path != httpcatalog.BrowserSeedPath
	}
	return unsafePath(path)
}

// noCookieWriter drops Set-Cookie from every response: a cookie the app or
// its API sets after a bearer call is a session credential of its own.
type noCookieWriter struct{ http.ResponseWriter }

func (w noCookieWriter) WriteHeader(status int) {
	w.ResponseWriter.Header().Del("Set-Cookie")
	w.ResponseWriter.WriteHeader(status)
}

func (w noCookieWriter) Write(b []byte) (int, error) {
	w.ResponseWriter.Header().Del("Set-Cookie")
	return w.ResponseWriter.Write(b)
}

func (w noCookieWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// browserSeed is a Playwright storage state for the app's origin. It holds
// what auth0-spa-js 2.x reads from localStorage, with the placeholder as the
// access token and an unsigned ID token carrying the test user's non-secret
// claims, plus the cookie that tells the client a session exists. The app
// never decodes the access token; it reads sub and org_id from the ID token.
// Nothing in it authenticates anything: the broker adds the real token.
func browserSeed(entry *httpcatalog.Entry, token httpcatalog.BrowserToken, scope *brokercore.ProxyScope, now time.Time) ([]byte, error) {
	b := entry.BrowserSession
	expires := now.Add(maxSeedLife)
	if !scope.NotAfter.IsZero() && scope.NotAfter.Before(expires) {
		expires = scope.NotAfter
	}
	if expires.Sub(now) < 2*time.Minute {
		return nil, errors.New("worker deadline too close for a browser session")
	}
	claims := map[string]any{}
	for k, v := range token.Claims {
		claims[k] = v
	}
	user := map[string]any{}
	for k, v := range claims {
		if k != "org_id" && k != "org_name" {
			user[k] = v
		}
	}
	claims["iss"] = "https://" + b.Auth0.Domain + "/"
	claims["aud"] = b.Auth0.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = expires.Unix()
	header := map[string]any{"alg": "none", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	idToken := encodedHeader + "." + encodedPayload + "."
	decodedClaims := map[string]any{"__raw": idToken}
	for k, v := range claims {
		decodedClaims[k] = v
	}
	userEntry, _ := json.Marshal(map[string]any{"id_token": idToken, "decodedToken": map[string]any{
		"encoded": map[string]string{"header": encodedHeader, "payload": encodedPayload, "signature": ""},
		"header":  header, "claims": decodedClaims, "user": user}})
	lifetime := int64(expires.Sub(now).Seconds())
	tokenEntry, _ := json.Marshal(map[string]any{"body": map[string]any{
		"access_token": entry.Placeholder, "expires_in": lifetime, "token_type": "Bearer",
		"scope": b.Auth0.Scope, "audience": b.Auth0.Audience, "client_id": b.Auth0.ClientID}, "expiresAt": expires.Unix()})
	prefix := "@@auth0spajs@@::" + b.Auth0.ClientID + "::"
	type item struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type cookie struct {
		Name     string  `json:"name"`
		Value    string  `json:"value"`
		Domain   string  `json:"domain"`
		Path     string  `json:"path"`
		Expires  float64 `json:"expires"`
		HTTPOnly bool    `json:"httpOnly"`
		Secure   bool    `json:"secure"`
		SameSite string  `json:"sameSite"`
	}
	origin := "https://" + b.AppHost
	if entry.Port != 443 {
		origin += ":" + strconv.Itoa(entry.Port)
	}
	state := map[string]any{
		"cookies": []cookie{{Name: "auth0." + b.Auth0.ClientID + ".is.authenticated", Value: "true", Domain: b.AppHost, Path: "/",
			Expires: float64(expires.Unix()), Secure: true, SameSite: "Lax"}},
		"origins": []map[string]any{{"origin": origin, "localStorage": []item{
			{Name: prefix + b.Auth0.Audience + "::" + b.Auth0.Scope, Value: string(tokenEntry)},
			{Name: prefix + "@@user@@", Value: string(userEntry)}}}},
	}
	return json.Marshal(state)
}

package mitm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// HeaderAdapter replaces the strict profile's per-vault services with an
// operator catalog: per-binding hosts, path prefixes and methods, a key from
// Vault injected into one header, and signed audit rows. Workers send at
// most a placeholder; the key exists only inside the broker.
type HeaderAdapter struct {
	// Catalog is read once per request, so a reloaded catalog applies to the
	// next request; an httpcatalog.Catalog or a live *httpcatalog.Source.
	Catalog interface{ Current() httpcatalog.Catalog }
	Keys    interface {
		Get(context.Context, httpcatalog.KeyRef) (httpcatalog.Secret, error)
		Invalidate(httpcatalog.KeyRef)
	}
	Audit interface {
		Admit() error
		Record(auditchain.Event) error
	}
	// GitTokens mints repository-scoped installation tokens for git and
	// github-api entries. Without it, those requests are refused.
	GitTokens interface {
		Token(ctx context.Context, app githubapp.App, repo string, permissions githubapp.Permissions) (githubapp.Token, error)
		Invalidate(app githubapp.App, repo string, permissions githubapp.Permissions)
	}
}

func (a *HeaderAdapter) valid() bool {
	return a != nil && a.Catalog != nil && a.Keys != nil && a.Audit != nil
}

const placeholderMarker = "__vault_"

// adapterDeny records a refusal before answering. If the row cannot be
// written the caller still learns nothing beyond "unavailable".
func (p *Proxy) adapterDeny(w http.ResponseWriter, event auditchain.Event, status int, outcome string) {
	event.Event, event.Outcome, event.Status = auditchain.EventDenied, outcome, status
	if p.adapter.Audit.Record(event) != nil {
		status = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(status), status)
}

// adapterUnauthenticatedDeny replaces the SQL audit for refusals that happen
// before identity is known, so every refusal lands in the signed trail.
func (p *Proxy) adapterUnauthenticatedDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int) {
	p.adapterDeny(w, auditchain.Event{Pool: a.ActorID, PodUID: a.WorkloadID, Method: auditMethod(r.Method)}, status, "refused")
}

func auditMethod(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		return m
	}
	return ""
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (p *Proxy) forwardCatalog(w http.ResponseWriter, r *http.Request, target, host string, port int, useTLS bool, scope *brokercore.ProxyScope) {
	a := p.adapter
	event := auditchain.Event{Session: newRequestID(), Method: auditMethod(r.Method)}
	if scope != nil {
		event.Pool, event.PodUID = scope.AgentID, scope.WorkloadID
	}
	w.Header().Set("X-Request-Id", event.Session)
	deny := func(status int, outcome string) { p.adapterDeny(w, event, status, outcome) }
	if scope == nil || scope.AgentID == "" || scope.UserID != "" {
		deny(http.StatusForbidden, "authentication")
		return
	}
	if err := a.Audit.Admit(); err != nil {
		deny(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if !useTLS {
		deny(http.StatusBadRequest, "plain_http")
		return
	}
	catalog := a.Catalog.Current()
	if git, ok, err := catalog.GitMatch(host, port, r.Method, r.URL.Path, r.URL.RawQuery, scope.AgentID); ok {
		p.forwardGit(w, r, target, scope, event, git, err)
		return
	}
	if api, ok, err := catalog.GitHubAPIMatch(host, port, r.Method, r.URL.Path, r.URL.RawQuery, scope.AgentID); ok {
		p.forwardGitHubAPI(w, r, target, scope, event, api, err)
		return
	}
	entry, err := catalog.Match(host, port, r.Method, r.URL.Path, scope.AgentID)
	if entry != nil {
		event.Binding = entry.Name
	}
	switch {
	case errors.Is(err, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(err, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case err != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || strings.Contains(r.URL.RawQuery, placeholderMarker) || r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 {
		deny(http.StatusBadRequest, "request_shape")
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
	case len(body) > 0 && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		deny(http.StatusBadRequest, "request_shape")
		return
	case bytes.Contains(body, []byte(placeholderMarker)):
		// Keys go only in the catalog header; a placeholder elsewhere would
		// reach the vendor verbatim.
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	}
	expectedCredential := entry.Placeholder
	if entry.Scheme != "" {
		expectedCredential = entry.Scheme + " " + entry.Placeholder
	}
	forwarded := http.Header{}
	for name, values := range r.Header {
		if name == entry.Header {
			if len(values) != 1 || values[0] != expectedCredential {
				deny(http.StatusBadRequest, "credential_header")
				return
			}
			continue
		}
		for _, v := range values {
			if strings.Contains(v, placeholderMarker) {
				deny(http.StatusBadRequest, "placeholder_misplaced")
				return
			}
		}
		if entry.ForwardsHeader(name) {
			forwarded[name] = append([]string(nil), values...)
		}
	}
	// One rate bucket per Pod, not per pool agent: a pool of many workers
	// shares one agent identity.
	enf := p.rateLimit.EnforceProxy(r.Context(), scope.AgentID+"/"+scope.WorkloadID, entry.Name)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer enf.Release()
	secret, err := a.Keys.Get(r.Context(), entry.Key)
	if err != nil {
		deny(http.StatusServiceUnavailable, "key_unavailable")
		return
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	out.Header = forwarded
	credential := secret.Value()
	if entry.Scheme != "" {
		credential = entry.Scheme + " " + credential
	}
	out.Header.Set(entry.Header, credential)
	out.Header.Set("Accept-Encoding", "identity")

	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	finish := func(status int, outcome string) {
		done := event
		done.Event, done.Outcome, done.Status = auditchain.EventHTTPResponse, outcome, status
		_ = a.Audit.Record(done)
	}
	needles := secretRepresentations(map[string]string{"key": secret.Value(), "credential": credential})
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func() {
		// The vendor may have rotated or revoked the key; read the newest next.
		a.Keys.Invalidate(entry.Key)
	}, nil)
}

// relayScreened sends out upstream and streams the response back, refusing
// compressed or upgraded responses and any that carry a needle. rejected runs
// on a 401 or 403. tooLarge, when set, reports that the request body was cut
// off at its limit.
func (p *Proxy) relayScreened(w http.ResponseWriter, out *http.Request, needles [][]byte, limit int64, finish func(int, string), rejected func(), tooLarge func() bool) {
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		if tooLarge != nil && tooLarge() {
			finish(http.StatusRequestEntityTooLarge, "request_too_large")
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		rejected()
	}
	encoding := resp.Header.Get("Content-Encoding")
	if resp.Header.Get("Upgrade") != "" || (encoding != "" && encoding != "identity") || headersContain(resp.Header, needles) {
		finish(http.StatusBadGateway, "response_refused")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	for name, values := range resp.Header {
		if brokercore.ShouldStripResponseHeader(name) || name == "X-Request-Id" || name == "Trailer" || name == "Content-Length" {
			continue
		}
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(resp.StatusCode)
	outcome := screenedCopy(w, resp.Body, needles, limit)
	finish(resp.StatusCode, outcome)
	if outcome != "completed" {
		// The status line is already sent; abort the connection so the worker
		// sees a truncated response rather than a clean end.
		panic(http.ErrAbortHandler)
	}
}

func unsafePath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, placeholderMarker) || strings.ContainsAny(path, "\\") || strings.Contains(path, "//") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func headersContain(h http.Header, needles [][]byte) bool {
	for name, values := range h {
		if containsSecret([]byte(name), needles) {
			return true
		}
		for _, v := range values {
			if containsSecret([]byte(v), needles) {
				return true
			}
		}
	}
	return false
}

// screenedCopy streams the body, flushing each chunk for server-sent events.
// It holds back only a tail that could be the start of the key, so a key
// split across reads is still seen before any part of it reaches the worker,
// while ordinary events pass through at once.
func screenedCopy(w http.ResponseWriter, body io.Reader, needles [][]byte, limit int64) string {
	flusher, _ := w.(http.Flusher)
	var pending []byte
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return "response_too_large"
			}
			pending = append(pending, buf[:n]...)
			if containsSecret(pending, needles) {
				return "secret_echo"
			}
			if release := len(pending) - partialSuffix(pending, needles); release > 0 {
				if _, werr := w.Write(pending[:release]); werr != nil {
					return "client_gone"
				}
				pending = append(pending[:0], pending[release:]...)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		if errors.Is(err, io.EOF) {
			if _, werr := w.Write(pending); werr != nil {
				return "client_gone"
			}
			return "completed"
		}
		if err != nil {
			return "upstream_error"
		}
	}
}

// partialSuffix is the length of the longest tail of data that is a proper
// prefix of some needle.
func partialSuffix(data []byte, needles [][]byte) int {
	longest := 0
	for _, needle := range needles {
		for k := min(len(needle)-1, len(data)); k > longest; k-- {
			if bytes.HasSuffix(data, needle[:k]) {
				longest = k
				break
			}
		}
	}
	return longest
}

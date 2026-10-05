package mitm

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// forwardGCP serves a gcp entry: the worker holds at most the placeholder,
// and the broker adds a token minted for this entry alone, either downscoped
// to one bucket prefix or impersonating the entry's own service account.
func (p *Proxy) forwardGCP(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, entry *httpcatalog.Entry, matchErr error) {
	a := p.adapter
	if entry != nil {
		event.Binding = entry.Name
	}
	deny := func(status int, outcome string) { p.adapterDeny(w, event, status, outcome) }
	switch {
	case errors.Is(matchErr, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(matchErr, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case matchErr != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	if a.GCPTokens == nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" ||
		unsafePath(r.URL.Path) || containsPlaceholder(r.URL.RawQuery) || r.Header.Get("Upgrade") != "" ||
		r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	if got := r.Header.Values("Authorization"); len(got) > 1 || (len(got) == 1 && got[0] != "Bearer "+entry.Placeholder) {
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
	case containsPlaceholder(string(body)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), scope.AgentID+"/"+scope.WorkloadID, entry.Name)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer enf.Release()
	token, err := a.GCPTokens.Token(r.Context(), entry)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	// RawPath keeps percent-encoded object names (a/b as a%2Fb) as sent.
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	for name, values := range r.Header {
		if entry.GCPForwardsHeader(name) {
			out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	credential := "Bearer " + token.Value()
	out.Header.Set("Authorization", credential)
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
	needles := secretRepresentations(map[string]string{"token": token.Value(), "credential": credential})
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func(*http.Response) { a.GCPTokens.Invalidate(entry) }, nil)
}

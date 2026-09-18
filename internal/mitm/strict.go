package mitm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

const strictResponseLimit = 1 << 20

var strictPlaceholder = regexp.MustCompile(`^__vault_[A-Z][A-Z0-9_]*__$`)

// strictAttempt never copies a request URL, arbitrary header, method, or body.
// Routing metadata is included only after an exact configured host matched.
func strictAttempt(scope *brokercore.ProxyScope, inject *brokercore.InjectResult, method, host, target, decision string) requestlog.Attempt {
	a := requestlog.Attempt{ActorType: "unknown", Method: "UNKNOWN", Decision: decision}
	if method == "GET" || method == "HEAD" {
		a.Method = method
	}
	if scope != nil {
		a.VaultID = scope.VaultID
		a.ActorType, a.ActorID = actorFromScope(scope)
		a.WorkloadID = scope.WorkloadID
		if a.ActorType == "" {
			a.ActorType = "unknown"
		}
	}
	if inject != nil && !inject.Passthrough && inject.MatchedHost == host {
		a.Destination = target
		a.Service = inject.MatchedName
		a.MappingIDs = append([]string(nil), inject.CredentialKeys...)
	}
	return a
}

// Bound storage admission synchronously, including overload denials. There is
// no per-denial background writer or queue to grow when storage is unavailable.
func (p *Proxy) beginStrictAudit(ctx context.Context, a requestlog.Attempt) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.durableAudit.Begin(ctx, a)
}

// finishStrictAudit detaches audit completion from client disconnects, but bounds
// the storage operation. An error leaves the acknowledged attempt unknown.
func (p *Proxy) finishStrictAudit(ctx context.Context, id, result string, status int) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return p.durableAudit.Finish(ctx, id, requestlog.Outcome{Result: result, Status: status})
}

func (p *Proxy) strictDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int) {
	a.Decision = "deny"
	if p.durableAudit == nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := p.beginStrictAudit(r.Context(), a)
	if err != nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Request-Id", id)
	if err := p.finishStrictAudit(r.Context(), id, "denied", status); err != nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// strictUnauthenticatedDeny deliberately omits unverified identity and routing.
func (p *Proxy) strictUnauthenticatedDeny(w http.ResponseWriter, r *http.Request, status int) {
	p.strictDeny(w, r, strictAttempt(nil, nil, r.Method, "", "", "deny"), status)
}

func (p *Proxy) forwardStrict(w http.ResponseWriter, r *http.Request, target, host string, port int, useTLS bool, scope *brokercore.ProxyScope) {
	attempt := strictAttempt(scope, nil, r.Method, host, target, "deny")
	deny := func(status int) { p.strictDeny(w, r, attempt, status) }
	// The first release is a read-only, header-only workflow. Reject unsupported
	// request surfaces before reading any Vault credential or opening upstream.
	if scope == nil {
		deny(http.StatusForbidden)
		return
	}
	if !useTLS || (r.Method != "GET" && r.Method != "HEAD") || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.User != nil || r.URL.Fragment != "" || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 || r.ContentLength != 0 {
		deny(http.StatusBadRequest)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || strings.ContainsAny(r.URL.Path, "{}%") || strings.Contains(r.URL.Path, "__") {
		deny(http.StatusBadRequest)
		return
	}
	// Refuse an absolute request target inside CONNECT; routing is always pinned
	// to the authenticated tunnel target, including the expected Host authority.
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) {
		deny(http.StatusBadRequest)
		return
	}
	if r.Body != nil {
		var b [1]byte
		n, err := r.Body.Read(b[:])
		if n != 0 || (err != nil && err != io.EOF) {
			deny(http.StatusBadRequest)
			return
		}
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), scope.ActorID(), scope.VaultID)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests)
		return
	}
	defer enf.Release()
	inject, err := p.creds.Inject(r.Context(), scope.VaultID, host, port, r.URL.Path)
	attempt = strictAttempt(scope, inject, r.Method, host, target, "deny")
	if err != nil {
		deny(http.StatusForbidden)
		return
	}
	// Wildcard destinations are outside this release: only configured exact hosts
	// may contribute routing metadata or receive credentials.
	if inject == nil || inject.Passthrough || inject.MatchedName == "" || inject.MatchedHost != host || len(inject.Headers) > 0 || len(inject.Substitutions) == 0 || len(inject.CredentialKeys) == 0 {
		deny(http.StatusForbidden)
		return
	}
	// Fixed parameters come only from the matched operator configuration. Incoming
	// query strings and bodies remain forbidden above, including exact copies.
	fixed := broker.Service{Host: inject.MatchedHost, Path: inject.MatchedPath, FixedQuery: inject.FixedQuery}
	if fixed.ValidateFixedQuery() != nil || (inject.FixedQuery != nil && (r.Method != http.MethodGet || inject.MatchedPath != r.URL.Path || r.URL.RawPath != "" || (inject.MatchedPort == nil && port != 443))) {
		deny(http.StatusForbidden)
		return
	}
	query := url.Values{}
	for key, value := range inject.FixedQuery {
		query.Set(key, value)
	}
	values := map[string]string{}
	for _, sub := range inject.Substitutions {
		if !strictPlaceholder.MatchString(sub.Placeholder) || len(sub.In) != 1 || sub.In[0] != "header" || sub.Value == "" || strings.ContainsAny(sub.Value, "\r\n") {
			deny(http.StatusBadRequest)
			return
		}
		if _, exists := values[sub.Placeholder]; exists {
			deny(http.StatusBadRequest)
			return
		}
		values[sub.Placeholder] = sub.Value
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: query.Encode()}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), nil)
	if err != nil {
		deny(http.StatusBadRequest)
		return
	}
	out.Host = expected
	// Reject unsupported marker locations before hop-by-hop headers are stripped.
	for name, vals := range r.Header {
		if strings.Contains(name, "__") || strings.ContainsAny(name, "{}") {
			deny(http.StatusBadRequest)
			return
		}
		if strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-Api-Key") {
			continue
		}
		for _, v := range vals {
			if strings.Contains(v, "__") || strings.ContainsAny(v, "{}") {
				deny(http.StatusBadRequest)
				return
			}
		}
	}
	brokercore.ApplyInjection(r.Header, out.Header, inject)
	used := map[string]bool{}
	responseSecrets := map[string]string{}
	for marker, value := range values {
		responseSecrets[marker] = value
	}
	for name, vals := range out.Header {
		if name == "Authorization" || name == "X-Api-Key" {
			if len(vals) != 1 {
				deny(http.StatusBadRequest)
				return
			}
			marker := vals[0]
			prefix := ""
			basic := name == "Authorization" && strings.HasPrefix(marker, "Basic ")
			if basic {
				encoded := strings.TrimPrefix(marker, "Basic ")
				decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
				// Only an exact placeholder username and empty password are supported.
				// Canonical encoding also excludes whitespace and ambiguous encodings.
				if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || !strings.HasSuffix(string(decoded), ":") {
					deny(http.StatusBadRequest)
					return
				}
				marker = strings.TrimSuffix(string(decoded), ":")
			}
			if !basic && name == "Authorization" && strings.HasPrefix(marker, "Bearer ") {
				prefix = "Bearer "
				marker = strings.TrimPrefix(marker, prefix)
			}
			secret, ok := values[marker]
			if !ok {
				deny(http.StatusBadRequest)
				return
			}
			if basic {
				if strings.ContainsRune(secret, ':') {
					deny(http.StatusBadRequest)
					return
				}
				out.SetBasicAuth(secret, "")
				// Base64(secret + ":") is not necessarily an encoding of secret
				// alone. Include the actual Basic payload in response screening.
				responseSecrets["basic:"+marker] = secret + ":"
			} else {
				out.Header.Set(name, prefix+secret)
			}
			used[marker] = true
		}
	}
	if len(used) == 0 || len(used) != len(values) {
		deny(http.StatusBadRequest)
		return
	}
	out.Header.Set("Accept-Encoding", "identity")
	attempt.Decision = "allow"
	if p.durableAudit == nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := p.beginStrictAudit(r.Context(), attempt)
	if err != nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Request-Id", id)
	finishFailure := func(status int) {
		if err := p.finishStrictAudit(r.Context(), id, "upstream_error", status); err != nil {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, http.StatusText(status), status)
	}
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		finishFailure(http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 && resp.StatusCode < 400 || resp.Header.Get("Upgrade") != "" || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" || resp.Uncompressed {
		finishFailure(http.StatusBadGateway)
		return
	}
	limit := int64(strictResponseLimit)
	if p.maxResponseBytes > 0 && p.maxResponseBytes < limit {
		limit = p.maxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		finishFailure(http.StatusBadGateway)
		return
	}
	needles := secretRepresentations(responseSecrets)
	if containsSecret(data, needles) {
		finishFailure(http.StatusBadGateway)
		return
	}
	for name, vals := range resp.Header {
		if containsSecret([]byte(name), needles) {
			finishFailure(http.StatusBadGateway)
			return
		}
		for _, v := range vals {
			if containsSecret([]byte(v), needles) {
				finishFailure(http.StatusBadGateway)
				return
			}
		}
	}
	for name, vals := range resp.Trailer {
		if containsSecret([]byte(name), needles) {
			finishFailure(http.StatusBadGateway)
			return
		}
		for _, v := range vals {
			if containsSecret([]byte(v), needles) {
				finishFailure(http.StatusBadGateway)
				return
			}
		}
	}
	if err := p.finishStrictAudit(r.Context(), id, "completed", resp.StatusCode); err != nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	for name, vals := range resp.Header {
		if brokercore.ShouldStripResponseHeader(name) || strings.EqualFold(name, "X-Request-Id") || strings.EqualFold(name, "Trailer") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

func secretRepresentations(values map[string]string) [][]byte {
	var out [][]byte
	for _, s := range values {
		encoded, _ := json.Marshal(s)
		for _, v := range []string{s, url.QueryEscape(s), url.PathEscape(s), base64.StdEncoding.EncodeToString([]byte(s)), base64.RawStdEncoding.EncodeToString([]byte(s)), base64.URLEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s)), hex.EncodeToString([]byte(s)), string(encoded[1 : len(encoded)-1])} {
			out = append(out, []byte(v))
		}
	}
	return out
}
func containsSecret(data []byte, needles [][]byte) bool {
	for _, n := range needles {
		if len(n) > 0 && bytes.Contains(data, n) {
			return true
		}
	}
	return false
}

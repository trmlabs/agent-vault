package mitm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// githubTokenPlaceholder is what a worker's GitHub client (gh, an SDK) may hold
// as its token. The broker replaces it; the worker never holds a real one.
const githubTokenPlaceholder = "__vault_GITHUB_TOKEN__"

// forwardGitHubAPI serves the GitHub REST endpoints an agent needs to open a
// pull request from its pool's own branch, read it and comment on it, for one
// listed repository, with a token minted for that repository with
// pull_requests write only. It can never approve, merge or update one:
// reviews, merges and edits are unlisted paths.
func (p *Proxy) forwardGitHubAPI(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, api httpcatalog.GitRequest, matchErr error) {
	a := p.adapter
	if api.Entry != nil {
		event.Binding = api.Entry.Name + "/" + api.Repo.Repo
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
	entry := api.Entry
	if a.GitTokens == nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 ||
		(api.Write && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	switch r.Header.Get("Authorization") {
	case "", "token " + githubTokenPlaceholder, "Bearer " + githubTokenPlaceholder:
	default:
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
	case bytes.Contains(body, []byte(placeholderMarker)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	case !api.Write && len(body) > 0:
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	if api.OpensPullRequest && !pullRequestFromPoolBranch(body, api.Repo.Repo, api.HeadPrefixes) {
		deny(http.StatusForbidden, "head")
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), scope.AgentID+"/"+scope.WorkloadID, entry.Name)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer enf.Release()
	app := githubapp.App{AppID: entry.Git.AppID, InstallationID: entry.Git.InstallationID}
	token, err := a.GitTokens.Token(r.Context(), app, api.Repo.Repo, githubapp.PullRequestsWrite)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path}
	method, outBody := http.MethodPost, io.Reader(bytes.NewReader(body))
	if !api.Write {
		method, outBody = http.MethodGet, nil
	}
	out, err := http.NewRequestWithContext(r.Context(), method, outURL.String(), outBody)
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	for _, name := range []string{"Accept", "Content-Type", "User-Agent", "X-Github-Api-Version"} {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[name] = append([]string(nil), v...)
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
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func(*http.Response) {
		a.GitTokens.Invalidate(app, api.Repo.Repo, githubapp.PullRequestsWrite)
	}, nil)
}

// pullRequestFromPoolBranch reports whether a create-pull-request body opens
// one from a branch of this repository under one of the pool's push prefixes.
// A head naming another owner ("owner:branch") or another repository, or a
// pull request made from an issue, is refused, as is any body that is not one
// JSON object.
func pullRequestFromPoolBranch(body []byte, repo string, prefixes []string) bool {
	var req map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil {
		return false
	}
	if _, ok := req["issue"]; ok {
		return false
	}
	if raw, ok := req["head_repo"]; ok {
		var headRepo string
		if json.Unmarshal(raw, &headRepo) != nil || !strings.EqualFold(headRepo, repo) {
			return false
		}
	}
	var head string
	if json.Unmarshal(req["head"], &head) != nil || strings.Contains(head, ":") || unsafeBranch(head) {
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(head, prefix) && len(head) > len(prefix) {
			return true
		}
	}
	return false
}

// unsafeBranch refuses a branch name with a path step that could leave the
// prefix (".."), a control character or a space.
func unsafeBranch(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return true
	}
	for _, c := range name {
		if c <= ' ' || c == 0x7f {
			return true
		}
	}
	return false
}

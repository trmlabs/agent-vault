package mitm

import (
	"bytes"
	"context"
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
	if api.OpensPullRequest {
		// GitHub receives the request rebuilt from the checked fields, never the
		// worker's bytes, so the two cannot read it differently.
		rebuilt, ok := pullRequestFromPoolBranch(body, api.HeadPrefixes)
		if !ok {
			deny(http.StatusForbidden, "head")
			return
		}
		body = rebuilt
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
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
	if api.CommentsOn > 0 && !p.commentsOnPoolPullRequest(r, target, expected, api, token.Value()) {
		deny(http.StatusForbidden, "comment_target")
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

// commentsOnPoolPullRequest reads the pull request a comment targets, with
// the same one-repository token, and reports whether its head is a branch of
// this repository under one of the pool's push prefixes. An issue that is not
// a pull request, a pull request from a fork or another pool's branch, or any
// failed read refuses the comment, so an agent comments only on its own pool's
// pull requests, never on people's.
func (p *Proxy) commentsOnPoolPullRequest(r *http.Request, target, host string, api httpcatalog.GitRequest, token string) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u := &url.URL{Scheme: "https", Host: target, Path: "/repos/" + api.Repo.Repo + "/pulls/" + strconv.FormatInt(api.CommentsOn, 10)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := p.upstream.RoundTrip(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var pr struct {
		Head struct {
			Ref  string `json:"ref"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(data, &pr) != nil ||
		pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, api.Repo.Repo) ||
		strings.Contains(pr.Head.Ref, ":") || unsafeBranch(pr.Head.Ref) {
		return false
	}
	for _, prefix := range api.HeadPrefixes {
		if strings.HasPrefix(pr.Head.Ref, prefix) && len(pr.Head.Ref) > len(prefix) {
			return true
		}
	}
	return false
}

// pullRequestFields are the only fields a pull request may be opened with.
var pullRequestFields = map[string]bool{"title": true, "body": true, "head": true, "base": true, "draft": true}

// pullRequestFromPoolBranch checks a create-pull-request body and returns it
// rebuilt from the checked values alone. The body must be one JSON object with
// only title, body, head and base (strings) and draft (a boolean), each at
// most once, in exactly that case; the head must be a branch of this
// repository under one of the pool's push prefixes. Anything else (an
// owner:branch head, head_repo, issue, a duplicate or unknown key, trailing
// data) is refused.
func pullRequestFromPoolBranch(body []byte, prefixes []string) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey || !pullRequestFields[key] || seen[strings.ToLower(key)] {
			return nil, false
		}
		seen[strings.ToLower(key)] = true
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, false
		}
		fields[key] = raw
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false // trailing data
	}
	var req struct {
		Title, Body, Head, Base string
		Draft                   bool
	}
	out := map[string]any{}
	for key, raw := range fields {
		var err error
		switch key {
		case "title":
			err = json.Unmarshal(raw, &req.Title)
			out[key] = req.Title
		case "body":
			err = json.Unmarshal(raw, &req.Body)
			out[key] = req.Body
		case "head":
			err = json.Unmarshal(raw, &req.Head)
			out[key] = req.Head
		case "base":
			err = json.Unmarshal(raw, &req.Base)
			out[key] = req.Base
		case "draft":
			err = json.Unmarshal(raw, &req.Draft)
			out[key] = req.Draft
		}
		if err != nil || string(raw) == "null" {
			return nil, false
		}
	}
	if strings.Contains(req.Head, ":") || unsafeBranch(req.Head) {
		return nil, false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(req.Head, prefix) && len(req.Head) > len(prefix) {
			rebuilt, err := json.Marshal(out)
			return rebuilt, err == nil
		}
	}
	return nil, false
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

package mitm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// forwardGit serves git smart-HTTP for a catalog git entry. The worker sends
// no credential; the broker adds a token minted for this one repository with
// contents read, or write only for a push to a write binding. GitHub's own
// branch protection still governs every push, and RefPrefixes narrow it.
func (p *Proxy) forwardGit(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, git httpcatalog.GitRequest, matchErr error) {
	a := p.adapter
	if git.Entry != nil {
		event.Binding = git.Entry.Name + "/" + git.Repo.Repo
	}
	deny := func(status int, outcome string) { p.adapterDeny(w, event, status, outcome) }
	switch {
	case errors.Is(matchErr, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(matchErr, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case errors.Is(matchErr, httpcatalog.ErrReadOnly):
		deny(http.StatusForbidden, "read_only")
		return
	case matchErr != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	entry := git.Entry
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || len(r.Trailer) > 0 ||
		(r.Method == http.MethodGet && r.ContentLength > 0) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	// The worker holds no credential, so it may send none.
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		deny(http.StatusBadRequest, "credential_header")
		return
	}
	// git compresses large fetch negotiations; nothing else may be encoded.
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && (encoding != "gzip" || git.Write || r.Method != http.MethodPost) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	body := &limitedBody{reader: r.Body, remaining: entry.MaxRequestBytes}
	var outBody io.Reader = body
	if git.Write && r.Method == http.MethodPost && len(git.Repo.RefPrefixes) > 0 {
		consumed, refs, err := readReceivePackCommands(body)
		if err != nil {
			deny(http.StatusBadRequest, "push_shape")
			return
		}
		for _, ref := range refs {
			if !hasAnyPrefix(ref, git.Repo.RefPrefixes) {
				deny(http.StatusForbidden, "ref_outside_binding")
				return
			}
		}
		outBody = io.MultiReader(bytes.NewReader(consumed), body)
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), scope.AgentID+"/"+scope.WorkloadID, entry.Name)
	if !enf.Allowed {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer enf.Release()
	app := githubapp.App{AppID: entry.Git.AppID, InstallationID: entry.Git.InstallationID}
	permissions := githubapp.ContentsRead
	if git.Write {
		permissions = githubapp.ContentsWrite
	}
	token, err := a.GitTokens.Token(r.Context(), app, git.Repo.Repo, permissions)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if r.Method == http.MethodGet {
		outBody = http.NoBody
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), outBody)
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	if r.Method == http.MethodPost {
		out.ContentLength = r.ContentLength // -1 streams chunked, as git does for large pushes
	}
	out.Host = expected
	for _, name := range []string{"Accept", "Content-Type", "User-Agent", "Git-Protocol", "Content-Encoding"} {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[name] = append([]string(nil), v...)
		}
	}
	payload := "x-access-token:" + token.Value()
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
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
	needles := secretRepresentations(map[string]string{"token": token.Value(), "basic": payload, "credential": credential})
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func() {
		a.GitTokens.Invalidate(app, git.Repo.Repo, permissions)
	}, body.exceeded.Load)
}

// limitedBody streams a request body and fails once it passes its limit.
type limitedBody struct {
	reader    io.Reader
	remaining int64
	exceeded  atomic.Bool
}

var errBodyTooLarge = errors.New("request body exceeds its limit")

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var probe [1]byte
		if n, _ := b.reader.Read(probe[:]); n > 0 {
			b.exceeded.Store(true)
			return 0, errBodyTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// readReceivePackCommands reads a push's command list (pkt-lines up to the
// flush) and returns the bytes read and every ref the push would change.
// Push certificates are refused, since their refs cannot be checked here.
func readReceivePackCommands(r io.Reader) ([]byte, []string, error) {
	var consumed []byte
	var refs []string
	for len(consumed) < 1<<20 {
		head := make([]byte, 4)
		if _, err := io.ReadFull(r, head); err != nil {
			return nil, nil, err
		}
		consumed = append(consumed, head...)
		n, err := strconv.ParseUint(string(head), 16, 16)
		if err != nil {
			return nil, nil, err
		}
		if n == 0 {
			if len(refs) == 0 {
				return nil, nil, errors.New("push without commands")
			}
			return consumed, refs, nil
		}
		if n < 5 {
			return nil, nil, errors.New("invalid pkt-line")
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
		consumed = append(consumed, payload...)
		line, _, _ := strings.Cut(strings.TrimSuffix(string(payload), "\n"), "\x00")
		switch {
		case strings.HasPrefix(line, "shallow "):
			continue
		case strings.HasPrefix(line, "push-cert"):
			return nil, nil, errors.New("push certificates are not supported")
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !objectID(fields[0]) || !objectID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return nil, nil, errors.New("invalid push command")
		}
		refs = append(refs, fields[2])
	}
	return nil, nil, errors.New("push command list too long")
}

func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

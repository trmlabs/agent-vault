package mitm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

type rsaSigner struct{ key *rsa.PrivateKey }

func (s rsaSigner) SignRS256(_ context.Context, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
}

// gitFixture runs real git through the broker against a fake GitHub: git
// http-backend for the smart-HTTP endpoints and a token endpoint that mints
// synthetic installation tokens and records what was requested.
type gitFixture struct {
	root, work, home, caFile, proxyURL string
	port                               int
	audit                              *adapterAudit
	mu                                 sync.Mutex
	minted                             map[string]string // token -> "repo:contents"
	requests                           []string          // contents permission per mint
	gitCalls                           []string          // repo:service seen with a valid token
}

func runGit(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	backend := filepath.Join(strings.TrimSpace(mustOutput(t, "git", "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	f := &gitFixture{root: t.TempDir(), work: t.TempDir(), home: t.TempDir(), audit: &adapterAudit{}, minted: map[string]string{}}
	env := f.env()
	for _, repo := range []string{"trmlabs/trm-b2b", "trmlabs/docs", "trmlabs/secret"} {
		bare := filepath.Join(f.root, repo+".git")
		if out, err := runGit(t, f.root, env, "init", "--bare", "--initial-branch=main", bare); err != nil {
			t.Fatal(out)
		}
		_, _ = runGit(t, bare, env, "config", "http.receivepack", "true")
		seed := t.TempDir()
		for _, args := range [][]string{{"init", "--initial-branch=main"}, {"commit", "--allow-empty", "-m", "seed"}, {"push", bare, "main"}} {
			if out, err := runGit(t, seed, env, args...); err != nil {
				t.Fatal(args, out)
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cgiHandler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + f.root, "GIT_HTTP_EXPORT_ALL=1"}}
	var seq int
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/app/installations/42/access_tokens") {
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			seq++
			token := fmt.Sprintf("ghs_syntheticgittoken%06d", seq)
			f.minted[token] = "trmlabs/" + body.Repositories[0] + ":" + body.Permissions["contents"]
			f.requests = append(f.requests, body.Permissions["contents"])
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "trmlabs/" + body.Repositories[0]}}})
			return
		}
		user, token, ok := r.BasicAuth()
		f.mu.Lock()
		scope, known := f.minted[token]
		f.mu.Unlock()
		repo, service := gitRequestScope(r)
		// Like GitHub: the token must name this repository, and a push needs write.
		if !ok || user != "x-access-token" || !known || !strings.HasPrefix(scope, repo+":") || (service == "git-receive-pack" && !strings.HasSuffix(scope, ":write")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.gitCalls = append(f.gitCalls, repo+":"+service)
		f.mu.Unlock()
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github","host":"example.com","port":%d,"kind":"git","pools":["pool-agent"],
		"git":{"appID":7,"installationID":42,"repos":[
			{"repo":"trmlabs/trm-b2b","access":"write","refPrefixes":["refs/heads/cursor/"]},
			{"repo":"trmlabs/docs","access":"read"}]}}]}`, f.port)))
	if err != nil {
		t.Fatal(err)
	}
	minter := &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", WorkloadID: "pod-uid-1"}
	proxyURL, _, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, GitTokens: minter}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	githubAddr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, githubAddr)
	}
	f.caFile = filepath.Join(f.home, "broker-ca.pem")
	if err := os.WriteFile(f.caFile, p.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	u := *proxyURL
	u.User = url.UserPassword("workload-token", "")
	f.proxyURL = u.String()
	return f
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Skip(name + " not available")
	}
	return string(out)
}

func gitRequestScope(r *http.Request) (repo, service string) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		return "", ""
	}
	repo = parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
	service = r.URL.Query().Get("service")
	if service == "" {
		service = parts[len(parts)-1]
	}
	return repo, service
}

// env isolates git from the developer's configuration and credentials.
func (f *gitFixture) env() []string {
	return []string{"HOME=" + f.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "PATH=" + os.Getenv("PATH"),
		"GIT_AUTHOR_NAME=worker", "GIT_AUTHOR_EMAIL=worker@example.invalid", "GIT_COMMITTER_NAME=worker", "GIT_COMMITTER_EMAIL=worker@example.invalid"}
}

// git runs as a worker would: through the broker, trusting its CA, with no
// credential of its own.
func (f *gitFixture) git(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-c", "http.proxy=" + f.proxyURL, "-c", "http.proxyAuthMethod=basic", "-c", "http.sslCAInfo=" + f.caFile,
		"-c", "credential.helper=", "-c", "protocol.version=2"}, args...)
	return runGit(t, dir, f.env(), full...)
}

func (f *gitFixture) remote(repo string) string {
	return fmt.Sprintf("https://example.com:%d/%s.git", f.port, repo)
}

func (f *gitFixture) bareRef(t *testing.T, repo, ref string) string {
	out, _ := runGit(t, filepath.Join(f.root, repo+".git"), f.env(), "rev-parse", "--verify", "-q", ref)
	return strings.TrimSpace(out)
}

func (f *gitFixture) tokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for token := range f.minted {
		out = append(out, token)
	}
	return out
}

func TestGitCloneAndPushThroughBrokerWithoutAToken(t *testing.T) {
	f := newGitFixture(t)
	clone := filepath.Join(f.work, "trm-b2b")
	out, err := f.git(t, f.work, "clone", f.remote("trmlabs/trm-b2b"), clone)
	if err != nil {
		t.Fatalf("clone: %s", out)
	}
	f.mu.Lock()
	fetchPermissions := append([]string(nil), f.requests...)
	f.mu.Unlock()
	if len(fetchPermissions) == 0 {
		t.Fatal("clone minted no token")
	}
	for _, permission := range fetchPermissions {
		if permission != "read" {
			t.Fatalf("clone minted %v, want read only", fetchPermissions)
		}
	}
	if _, err := f.git(t, clone, "checkout", "-b", "cursor/feature"); err != nil {
		t.Fatal("branch")
	}
	if out, err := f.git(t, clone, "commit", "--allow-empty", "-m", "agent change"); err != nil {
		t.Fatal(out)
	}
	if out, err := f.git(t, clone, "push", "origin", "cursor/feature"); err != nil {
		t.Fatalf("push to an allowed prefix: %s", out)
	}
	if f.bareRef(t, "trmlabs/trm-b2b", "refs/heads/cursor/feature") == "" {
		t.Fatal("pushed branch missing upstream")
	}
	f.mu.Lock()
	sawWrite := strings.Contains(strings.Join(f.requests, ","), "write")
	f.mu.Unlock()
	if !sawWrite {
		t.Fatal("push did not mint a write token")
	}
	// The worker's clone, its config and git's output never hold a token.
	config, _ := os.ReadFile(filepath.Join(clone, ".git", "config"))
	for _, token := range f.tokens() {
		if strings.Contains(out, token) || strings.Contains(string(config), token) {
			t.Fatal("token reached the worker")
		}
		for _, e := range f.audit.all() {
			if strings.Contains(fmt.Sprint(e), token) {
				t.Fatal("token in an audit row")
			}
		}
	}
	completed := 0
	for _, e := range f.audit.all() {
		if e.Event == auditchain.EventHTTPResponse && e.Binding == "github/trmlabs/trm-b2b" && e.Outcome == "completed" && e.PodUID == "pod-uid-1" {
			completed++
		}
	}
	if completed < 4 {
		t.Fatalf("audit recorded %d completed git calls", completed)
	}
}

func TestGitPushesOutsideTheBindingAreRefused(t *testing.T) {
	f := newGitFixture(t)
	clone := filepath.Join(f.work, "trm-b2b")
	if out, err := f.git(t, f.work, "clone", f.remote("trmlabs/trm-b2b"), clone); err != nil {
		t.Fatal(out)
	}
	before := f.bareRef(t, "trmlabs/trm-b2b", "refs/heads/main")
	if out, err := f.git(t, clone, "commit", "--allow-empty", "-m", "direct to main"); err != nil {
		t.Fatal(out)
	}
	if out, err := f.git(t, clone, "push", "origin", "main"); err == nil {
		t.Fatalf("push to main accepted: %s", out)
	}
	if f.bareRef(t, "trmlabs/trm-b2b", "refs/heads/main") != before || f.audit.last().Outcome != "ref_outside_binding" {
		t.Fatalf("main changed or refusal not recorded: %+v", f.audit.last())
	}
	if out, err := f.git(t, clone, "push", "origin", "HEAD:refs/tags/v9"); err == nil {
		t.Fatalf("tag push accepted: %s", out)
	}

	docs := filepath.Join(f.work, "docs")
	if out, err := f.git(t, f.work, "clone", f.remote("trmlabs/docs"), docs); err != nil {
		t.Fatalf("read-only clone: %s", out)
	}
	_, _ = f.git(t, docs, "checkout", "-b", "cursor/x")
	_, _ = f.git(t, docs, "commit", "--allow-empty", "-m", "x")
	if out, err := f.git(t, docs, "push", "origin", "cursor/x"); err == nil || f.audit.last().Outcome != "read_only" {
		t.Fatalf("push to a read-only binding: %s %+v", out, f.audit.last())
	}
	f.mu.Lock()
	if strings.Contains(strings.Join(f.gitCalls, ","), "trmlabs/docs:git-receive-pack") {
		t.Error("a push to the read-only repository reached GitHub")
	}
	f.mu.Unlock()

	if out, err := f.git(t, f.work, "clone", f.remote("trmlabs/secret"), filepath.Join(f.work, "secret")); err == nil || f.audit.last().Outcome != "unlisted" {
		t.Fatalf("unlisted repository cloned: %s", out)
	}
}

func TestGitRequestsCarryingACredentialAreRefused(t *testing.T) {
	f := newGitFixture(t)
	out, err := f.git(t, f.work, "-c", "http.extraHeader=Authorization: Basic d29ya2VyOnRva2Vu", "ls-remote", f.remote("trmlabs/trm-b2b"))
	if err == nil || f.audit.last().Outcome != "credential_header" {
		t.Fatalf("worker credential forwarded: %s %+v", out, f.audit.last())
	}
}

func TestReceivePackCommandParsing(t *testing.T) {
	zero, one := strings.Repeat("0", 40), strings.Repeat("a", 40)
	pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
	body := pkt("shallow "+one+"\n") + pkt(zero+" "+one+" refs/heads/cursor/a\x00report-status side-band-64k\n") + pkt(one+" "+zero+" refs/heads/cursor/b\n") + "0000PACK..."
	consumed, refs, err := readReceivePackCommands(strings.NewReader(body))
	if err != nil || strings.Join(refs, ",") != "refs/heads/cursor/a,refs/heads/cursor/b" || string(consumed)+"PACK..." != body {
		t.Fatalf("parse: %v %v", refs, err)
	}
	for name, bad := range map[string]string{
		"push certificate": pkt("push-cert\x00caps\n") + "0000",
		"no commands":      "0000",
		"bad object":       pkt("zz "+one+" refs/heads/x\n") + "0000",
		"bad length":       "00zz",
		"truncated":        pkt(zero + " " + one + " refs/heads/x\n")[:10],
	} {
		if _, _, err := readReceivePackCommands(strings.NewReader(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

package httpcatalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const gitEntry = `{"name":"github","host":"github.com","kind":"git","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[
		{"repo":"TRMLabs/trm-b2b","access":"write","refPrefixes":["refs/heads/cursor/"]},
		{"repo":"trmlabs/docs","access":"read"}]}}`

func TestGitEntriesParseAndReject(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.Git.Repos[0].Repo != "trmlabs/trm-b2b" || e.MaxRequestBytes != 1<<30 || e.MaxResponseBytes != 4<<30 || !c.HasHost("github.com", 443) {
		t.Fatalf("normalized: %+v", e)
	}
	for name, doc := range map[string]string{
		"header fields":      strings.Replace(gitEntry, `"kind":"git"`, `"kind":"git","header":"Authorization"`, 1),
		"no app":             strings.Replace(gitEntry, `"appID":7`, `"appID":0`, 1),
		"bad access":         strings.Replace(gitEntry, `"access":"read"`, `"access":"admin"`, 1),
		"read with prefixes": strings.Replace(gitEntry, `"access":"read"`, `"access":"read","refPrefixes":["refs/heads/x/"]`, 1),
		"bad ref prefix":     strings.Replace(gitEntry, `refs/heads/cursor/`, `heads/cursor`, 1),
		"traversal repo":     strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/..`, 1),
		"dot git repo":       strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/docs.git`, 1),
		"duplicate repo":     strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/trm-b2b`, 1),
		"unknown kind":       strings.Replace(gitEntry, `"kind":"git"`, `"kind":"ssh"`, 1),
		"git without kind":   strings.Replace(gitEntry, `"kind":"git",`, ``, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	header := strings.Replace(validEntry, `"serpapi.com"`, `"github.com"`, 1)
	if _, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + header + `]}`)); err == nil {
		t.Error("git and header entries mixed on one host")
	}
	twin := strings.Replace(strings.Replace(gitEntry, `"github"`, `"github-2"`, 1), `trmlabs/docs`, `trmlabs/other`, 1)
	if _, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + twin + `]}`)); err == nil {
		t.Error("a repository bound twice")
	}
}

func TestGitMatchEndpointsAndAccess(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + validEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, query, pool, repo string
		write                           bool
		err                             error
	}{
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-upload-pack", "pool-a", "trmlabs/trm-b2b", false, nil},
		{"POST", "/TRMLabs/trm-b2b/git-upload-pack", "", "pool-a", "trmlabs/trm-b2b", false, nil},
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/trm-b2b", true, nil},
		{"POST", "/trmlabs/trm-b2b.git/git-receive-pack", "", "pool-a", "trmlabs/trm-b2b", true, nil},
		{"POST", "/trmlabs/docs.git/git-upload-pack", "", "pool-a", "trmlabs/docs", false, nil},
		{"POST", "/trmlabs/docs.git/git-receive-pack", "", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"GET", "/trmlabs/docs.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"POST", "/trmlabs/trm-b2b.git/git-upload-pack", "", "pool-b", "trmlabs/trm-b2b", false, ErrPool},
		{"POST", "/trmlabs/secret.git/git-upload-pack", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-upload-pack&x=1", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/info/lfs/objects/batch", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/git-upload-pack", "", "pool-a", "", false, ErrMethod},
		{"GET", "/trmlabs/trm-b2b", "", "pool-a", "", false, ErrUnlisted},
	} {
		got, ok, err := c.GitMatch("github.com", 443, tc.method, tc.path, tc.query, tc.pool)
		if !ok || !errors.Is(err, tc.err) || (tc.repo != "" && (got.Repo.Repo != tc.repo || got.Write != tc.write)) {
			t.Errorf("%s %s?%s: ok=%v repo=%q write=%v err=%v", tc.method, tc.path, tc.query, ok, got.Repo.Repo, got.Write, err)
		}
	}
	if _, ok, _ := c.GitMatch("serpapi.com", 443, "GET", "/search", "", "pool-a"); ok {
		t.Fatal("header host routed to git")
	}
	if e, err := c.Match("github.com", 443, "POST", "/trmlabs/trm-b2b.git/git-upload-pack", "pool-a"); e != nil || !errors.Is(err, ErrUnlisted) {
		t.Fatal("git entry matched as a header entry")
	}
}

const apiEntry = `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/trm-b2b","access":"write"}]}}`

func TestGitHubAPIEntries(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Entries()[1]; e.MaxRequestBytes != 1<<20 || e.MaxResponseBytes != 8<<20 {
		t.Fatalf("api limits: %d %d", e.MaxRequestBytes, e.MaxResponseBytes)
	}
	for name, doc := range map[string]string{
		"read access":  strings.Replace(apiEntry, `"access":"write"`, `"access":"read"`, 1),
		"ref prefixes": strings.Replace(apiEntry, `"access":"write"`, `"access":"write","refPrefixes":["refs/heads/x/"]`, 1),
		"large body":   strings.Replace(apiEntry, `"pools"`, `"maxRequestBytes":33554432,"pools"`, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, tc := range []struct {
		method, path, query, pool string
		err                       error
	}{
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", nil},
		{"POST", "/repos/TRMLabs/trm-b2b/issues/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/comments/99/replies", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/reviews", "", "pool-a", ErrUnlisted},
		{"PUT", "/repos/trmlabs/trm-b2b/pulls/12/merge", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/issues/abc/comments", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/git/refs", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/other/pulls", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "per_page=1", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12/files", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-b", ErrPool},
		{"POST", "/user/repos", "", "pool-a", ErrUnlisted},
	} {
		if _, ok, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, tc.pool); !ok || !errors.Is(err, tc.err) {
			t.Errorf("%s %s: ok=%v err=%v", tc.method, tc.path, ok, err)
		}
	}
	if _, ok, _ := c.GitHubAPIMatch("github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); ok {
		t.Fatal("git host routed to the API")
	}
	// Opening a pull request carries the pool's own push prefixes; other routes do not.
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); !m.OpensPullRequest || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("create: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/issues/7/comments", "", "pool-a"); m.OpensPullRequest || m.CommentsOn != 7 || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("comment: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls/8/comments/99/replies", "", "pool-a"); m.CommentsOn != 8 {
		t.Fatalf("reply: %+v", m)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/issues/007/comments", "", "pool-a"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("a padded number matched: %v", err)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/trm-b2b/pulls/1", "", "pool-a"); m.Write {
		t.Fatalf("read marked as a write: %+v", m)
	}
	// Without a git entry for the pool, there is no branch to open one from.
	alone, err := Parse([]byte(`{"entries":[` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m, _, _ := alone.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); !m.OpensPullRequest || len(m.HeadPrefixes) != 0 {
		t.Fatalf("no git entry: %+v", m)
	}
}

// A scope with no catalog pool (a non-pool agent, or an Attestor that set
// none) matches no grant of any kind, even on a listed route.
func TestEmptyPoolMatchesNoGrant(t *testing.T) {
	doc := `{"pools":[{"name":"pool-a","namespace":"agents","serviceAccount":"worker"}],"entries":[` + validEntry + `,` + gitEntry + `,` + apiEntry + `,
		{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"core","mount":"database","role":"r-readonly"}}]}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Match("serpapi.com", 443, "GET", "/search", ""); !errors.Is(err, ErrPool) {
		t.Errorf("header entry: %v", err)
	}
	if _, _, err := c.GitMatch("github.com", 443, "POST", "/trmlabs/trm-b2b.git/git-upload-pack", "", ""); !errors.Is(err, ErrPool) {
		t.Errorf("git entry: %v", err)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", ""); !errors.Is(err, ErrPool) {
		t.Errorf("github-api entry: %v", err)
	}
	if _, err := c.Database("core", ""); !errors.Is(err, ErrPool) {
		t.Errorf("postgres entry: %v", err)
	}
}

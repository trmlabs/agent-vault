package leakcheck

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Names that must not appear, by the SHA-256 of the lowercase token, so this
// file does not publish them itself. A token is a run of letters, digits, "_"
// and "-", so a dotted host is checked one label at a time.
var deniedTokens = map[string]string{
	"ca67af247429a62b379e673e63927761de1dbbff441abc4805a0a060d4d33ff6": "internal domain",
	"e14b2129a1f577184e79a136d011d4a904319500b7cbc952a6d6e03da7fb7eee": "cloud project",
	"a5a8fc7454bdd02eeb587646d619058976b9fccaf3c9aa56789945982318b3d2": "cluster name",
	"d6da43666eba5f72fb8c94ce207ca26d99ba0c1c660a29ce662ff7126dfb107a": "cloud project",
	"c1b6f329020c381ed2c45886e7d0a65157c5a0f401aa28c120cc6bf198ca31d7": "cloud project",
	"20c2f2ca25d854774a621dd06194a34d56cc181343bdce1fa59eb4d9bccb888b": "cloud project",
	"5c0a45da8c29b9287b06ab5feb512e46ec57f45d5d70bcaaedb31aa01762d812": "storage bucket",
	"4fe221c0146513fb74b5221101fd68c6ceb344fa5ff20d3e08466e2c4acb4a60": "cloud folder or profile",
	"7a25af561965d253eff5c923926827a9c2eb6f9143399b8339f28d7ba64fae53": "cloud folder or profile",
	"3f2a67eb77e5c4cc0844a333e83c6fb22ca99cc8cb2d8cdbda0e36fd0c9a76f7": "cloud folder",
	"990b28759b479807a2eecaed2889608fc57b544873e3c218c0ab0eeda5a12400": "cloud folder",
	"8fc9fc91d827821d3370a922c662f5f1054192edd751c5a7d6500f68c8b6e6c3": "Vault auth mount",
	"d471b2c4834d7787014c8b163377b03726d05e0dfc2d8e77c86ecf141d3785c2": "identity client ID",
	"6c8c06f39af92c31cff20e3514897d0668ef6dd1e4d9154db8b172b6ea96820e": "identity organization ID",
}

var (
	token = regexp.MustCompile(`[A-Za-z0-9_-]{3,}`)
	// Hosts under the operator's domains. The annotation keys the broker reads
	// (gatehouse.trmlabs.com/...) are names, not hosts, and stay allowed.
	internalHost = regexp.MustCompile(`(?i)[a-z0-9-]+(\.[a-z0-9-]+)*\.trmlabs(-[a-z]+)?\.[a-z]{2,}`)
	otherDomain  = regexp.MustCompile(`(?i)trmlabs-[a-z]+\.[a-z]{2,}`)
	email        = regexp.MustCompile(`(?i)[a-z0-9._%+-]*@-?trmlabs\.[a-z]{2,}`)
	// An identity organization ID has the shape org_ and 16 characters; tests
	// use short synthetic ones.
	orgID = regexp.MustCompile(`\borg_[A-Za-z0-9]{16}\b`)
	// Service accounts are named in an example-* project only.
	serviceAccount = regexp.MustCompile(`[a-z0-9-]+@([a-z][a-z0-9-]*)\.iam\.gserviceaccount\.com`)
)

// The repository's published security contact is the one allowed address.
const securityContact = "security@trmlabs.com"

func TestNoInternalNames(t *testing.T) {
	root, files := trackedFiles(t)
	for _, name := range files {
		if strings.HasPrefix(name, "internal/leakcheck/") || skipped(name) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for n := 1; scanner.Scan(); n++ {
			for _, problem := range problems(name, scanner.Text()) {
				t.Errorf("%s:%d: %s; use an example.com style placeholder", name, n, problem)
			}
		}
	}
}

func problems(name, line string) []string {
	var found []string
	for _, loc := range internalHost.FindAllStringIndex(line, -1) {
		if !strings.HasPrefix(line[loc[1]:], "/") {
			found = append(found, "internal hostname")
		}
	}
	if otherDomain.MatchString(line) {
		found = append(found, "internal domain")
	}
	for _, m := range email.FindAllString(line, -1) {
		if name != "SECURITY.md" || !strings.EqualFold(m, securityContact) {
			found = append(found, "internal email address")
		}
	}
	if orgID.MatchString(line) {
		found = append(found, "identity organization ID")
	}
	for _, m := range serviceAccount.FindAllStringSubmatch(line, -1) {
		if !strings.HasPrefix(m[1], "example") {
			found = append(found, "cloud service account")
		}
	}
	for _, tok := range token.FindAllString(line, -1) {
		sum := sha256.Sum256([]byte(strings.ToLower(tok)))
		if kind, ok := deniedTokens[hex.EncodeToString(sum[:])]; ok {
			found = append(found, kind)
		}
	}
	return found
}

func skipped(name string) bool {
	base := filepath.Base(name)
	return base == "go.sum" || base == "package-lock.json" || strings.Contains(name, "node_modules/")
}

func trackedFiles(t *testing.T) (string, []string) {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("not a git checkout")
	}
	root := strings.TrimSpace(string(out))
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	list, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(string(list), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return root, files
}

func TestProblems(t *testing.T) {
	for line, want := range map[string]bool{
		`"host": "api.staging.example.com"`:                  false,
		`"host": "api.corp.trmlabs.com"`:                     true,
		`annotation gatehouse.trmlabs.com/requester`:         false,
		`"https://trmlabs.com/email"`:                        false,
		`alice@example.com`:                                  false,
		`alice@trmlabs.com`:                                  true,
		`"orgID": "org_synthetic"`:                           false,
		`"orgID": "org_ABCDEFGHIJKLMNOP"`:                    true,
		`bq-cases@example-analytics.iam.gserviceaccount.com`: false,
		`bq-cases@acme-analytics.iam.gserviceaccount.com`:    true,
	} {
		if got := len(problems("x.go", line)) > 0; got != want {
			t.Errorf("%s: flagged %v, want %v", line, got, want)
		}
	}
	if len(problems("SECURITY.md", securityContact)) != 0 {
		t.Error("the security contact is flagged in SECURITY.md")
	}
}

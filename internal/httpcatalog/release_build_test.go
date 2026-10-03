package httpcatalog

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The plaintext-database switch exists only in the e2e build. These tests
// keep it out of what ships: no release build file sets the e2e tag, and a
// default build of the catalog and the server command has no way to turn
// the switch on.

var e2eTag = regexp.MustCompile(`\be2e\b`)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from %s", root)
	}
	return root
}

func TestReleaseBuildsNeverSetTheE2ETag(t *testing.T) {
	root := repoRoot(t)
	files := []string{"Dockerfile", ".goreleaser.yml", "Makefile"}
	workflows, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", "release*.yml"))
	for _, w := range workflows {
		rel, _ := filepath.Rel(root, w)
		files = append(files, rel)
	}
	if len(workflows) == 0 {
		t.Fatal("no release workflow found; update this test with the release build's files")
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if e2eTag.MatchString(line) {
				t.Errorf("%s:%d mentions the e2e build tag; release builds must not set it: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestDefaultBuildHasNoPlaintextSwitch(t *testing.T) {
	root := repoRoot(t)
	for dir, forbidden := range map[string][]string{
		"internal/httpcatalog": {"AllowPlaintextDatabases"},
		"cmd":                  {"AllowPlaintextDatabases"},
	} {
		pkg, err := build.Default.ImportDir(filepath.Join(root, dir), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range pkg.GoFiles {
			parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, file), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(parsed, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncDecl:
					for _, name := range forbidden {
						if x.Name.Name == name {
							t.Errorf("%s/%s declares %s in the default build", dir, file, name)
						}
					}
				case *ast.SelectorExpr:
					for _, name := range forbidden {
						if x.Sel.Name == name {
							t.Errorf("%s/%s calls %s in the default build", dir, file, name)
						}
					}
				case *ast.CallExpr:
					// Only the e2e build may store true in the switch.
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Store" {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "plaintextDatabases" {
							t.Errorf("%s/%s sets plaintextDatabases in the default build", dir, file)
						}
					}
				}
				return true
			})
		}
	}
}

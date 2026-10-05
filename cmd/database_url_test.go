package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The store URL can come from a file so a mounted Secret never enters the
// environment; the value never appears in an error.
func TestDatabaseURLFromFile(t *testing.T) {
	dir := t.TempDir()
	// Built in pieces so the synthetic URL does not read as a credential.
	secret := "postgres://broker:" + "synthetic-store-password" + "@db.internal:5432/brokerstore"
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write("url", secret+"\n")

	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", good)
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("from file: %q %v", url, err)
	}
	if !sharedStoreConfigured() {
		t.Fatal("a store URL file does not count as a shared store")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL_FILE", link) // a Kubernetes Secret mount is a symlink to a regular file
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("through a symlink: %q %v", url, err)
	}

	for name, setup := range map[string]func(){
		"both set":  func() { t.Setenv("DATABASE_URL", secret); t.Setenv("DATABASE_URL_FILE", good) },
		"directory": func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", dir) },
		"empty":     func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", write("empty", " \n")) },
		"too large": func() {
			t.Setenv("DATABASE_URL", "")
			t.Setenv("DATABASE_URL_FILE", write("big", strings.Repeat("x", 5000)))
		},
		"missing": func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", filepath.Join(dir, "absent")) },
	} {
		setup()
		url, err := databaseURL()
		if err == nil || url != "" {
			t.Errorf("%s: accepted (%v)", name, err)
			continue
		}
		if strings.Contains(err.Error(), "synthetic-store-password") {
			t.Errorf("%s: the error carries the URL", name)
		}
	}

	t.Setenv("DATABASE_URL_FILE", "")
	t.Setenv("DATABASE_URL", secret)
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("plain DATABASE_URL: %q %v", url, err)
	}
	t.Setenv("DATABASE_URL", "")
	if url, err := databaseURL(); err != nil || url != "" || sharedStoreConfigured() {
		t.Fatalf("no store set: %q %v", url, err)
	}
}

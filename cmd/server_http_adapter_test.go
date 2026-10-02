package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
)

func TestHTTPHeaderAdapterStartupRefusals(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	if adapter, err := httpHeaderAdapter(context.Background(), s, env(nil)); adapter != nil || err != nil {
		t.Fatalf("adapter without a catalog: %v", err)
	}
	if _, err := httpHeaderAdapter(context.Background(), s, env(map[string]string{"AGENT_VAULT_HTTP_CATALOG_FILE": "unused"})); err == nil || !strings.Contains(err.Error(), "CREDENTIAL_PROXY") {
		t.Fatalf("adapter outside the credential proxy: %v", err)
	}
	s.EnableCredentialProxy()
	bad := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(bad, []byte(`{"entries":[{"name":"x","host":"*.example.com"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := httpHeaderAdapter(context.Background(), s, env(map[string]string{"AGENT_VAULT_HTTP_CATALOG_FILE": bad})); err == nil {
		t.Fatal("invalid catalog accepted")
	}
	good := filepath.Join(t.TempDir(), "good.json")
	if err := os.WriteFile(good, []byte(`{"entries":[{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search"],"methods":["GET"],
		"header":"X-Api-Key","placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"vendors/serpapi","field":"key"},"pools":["pool-a"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := httpHeaderAdapter(context.Background(), s, env(map[string]string{"AGENT_VAULT_HTTP_CATALOG_FILE": good})); err == nil || !strings.Contains(err.Error(), "Vault client") {
		t.Fatalf("adapter without Vault: %v", err)
	}
}

func TestGitHubAppSignerRequiresAKeyLocation(t *testing.T) {
	if _, err := githubAppSigner(nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "GITHUB_APP") {
		t.Fatalf("git entries without an App key location: %v", err)
	}
}

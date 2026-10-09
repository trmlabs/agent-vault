package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
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

func TestCatalogTakesOneVaultLocation(t *testing.T) {
	env := map[string]string{"AGENT_VAULT_CATALOG_VAULT_PATH": "gatehouse/catalog", "AGENT_VAULT_CATALOG_VAULT_PREFIX": "gatehouse/catalog"}
	if _, err := brokerCatalog(context.Background(), nil, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both locations accepted: %v", err)
	}
	delete(env, "AGENT_VAULT_CATALOG_VAULT_PATH")
	if _, err := brokerCatalog(context.Background(), nil, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "Vault client") {
		t.Fatalf("per-entry catalog without Vault: %v", err)
	}
}

func TestGitHubAppSignerRequiresAKeyLocation(t *testing.T) {
	if _, err := githubAppSigner(nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "GITHUB_APP") {
		t.Fatalf("git entries without an App key location: %v", err)
	}
}

// The broker's Auth0 logins reach only an Auth0 domain the catalog names, on
// 443, and never follow a redirect.
func TestAuth0ClientDialsOnlyCatalogDomains(t *testing.T) {
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[{"name":"staging-app","kind":"browser-session","host":"api.example.com",
		"placeholder":"__vault_STAGING_APP__","pools":["pool-a"],"pathPrefixes":["/v1"],"browserSession":{"appHost":"app.example.com",
		"auth0":{"domain":"auth.example.com","clientID":"spaClient1","audience":"https://api.example.com","realm":"Username-Password-Authentication",
		"tokenClient":{"mount":"gatehouse","path":"browser/client"}},"user":{"mount":"gatehouse","path":"browser/qa-user"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	client := auth0Client(catalog, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, net.ErrClosed
	})
	dial := client.Transport.(*http.Transport).DialContext
	for _, addr := range []string{"auth.example.com:443", "AUTH.example.com:443"} {
		if _, err := dial(context.Background(), "tcp", addr); err != net.ErrClosed {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
	for _, addr := range []string{"api.example.com:443", "collector.example.net:443", "auth.example.com:80", "auth.example.com"} {
		if _, err := dial(context.Background(), "tcp", addr); err == nil || err == net.ErrClosed {
			t.Errorf("%s dialed", addr)
		}
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed %v", dialed)
	}
	if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects followed")
	}
}

// The broker's automated-auth logins reach only a service address the catalog
// names, and never follow a redirect.
func TestAutomatedAuthClientDialsOnlyCatalogServices(t *testing.T) {
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[{"name":"staging-app","kind":"browser-session","host":"api.example.com",
		"placeholder":"__vault_STAGING_APP__","pools":["pool-a"],"pathPrefixes":["/v1"],"browserSession":{"appHost":"app.example.com",
		"auth0":{"domain":"auth.example.com","clientID":"spaClient1","audience":"https://api.example.com","login":"automated-auth"},
		"automatedAuth":{"url":"https://automated-auth.automated-auth.svc.cluster.local:8443","profile":"app-staging","orgID":"org_synthetic",
		"key":{"mount":"gatehouse","path":"browser/automated-auth"}},"user":{"mount":"gatehouse","path":"browser/qa-user"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	client := automatedAuthClient(catalog, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, net.ErrClosed
	})
	dial := client.Transport.(*http.Transport).DialContext
	if _, err := dial(context.Background(), "tcp", "automated-auth.automated-auth.svc.cluster.local:8443"); err != net.ErrClosed {
		t.Errorf("catalog service refused: %v", err)
	}
	for _, addr := range []string{"automated-auth.automated-auth.svc.cluster.local:443", "auth.example.com:443", "collector.example.net:8443"} {
		if _, err := dial(context.Background(), "tcp", addr); err == nil || err == net.ErrClosed {
			t.Errorf("%s dialed", addr)
		}
	}
	if len(dialed) != 1 {
		t.Fatalf("dialed %v", dialed)
	}
	if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects followed")
	}
}

// A drain longer than 65 s would outlast the Pod's 75 s grace with the
// database cleanup and the Vault revoke, so the server refuses to start.
func TestShutdownSecondsMustFitTheGrace(t *testing.T) {
	for raw, ok := range map[string]bool{"": true, "0": true, "60": true, "65": true, "66": false, "300": false, "-1": false, "1m": false} {
		err := checkShutdownSeconds(func(string) string { return raw })
		if (err == nil) != ok {
			t.Errorf("AGENT_VAULT_SHUTDOWN_SECONDS=%q: %v", raw, err)
		}
	}
	t.Setenv("AGENT_VAULT_SHUTDOWN_SECONDS", "75")
	if err := serverCmd.RunE(serverCmd, nil); err == nil || !strings.Contains(err.Error(), "AGENT_VAULT_SHUTDOWN_SECONDS") {
		t.Fatalf("server started with a 75 s drain: %v", err)
	}
}

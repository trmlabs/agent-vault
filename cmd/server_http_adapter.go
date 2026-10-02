package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/server"
)

var sharedCatalog struct {
	sync.Mutex
	source  *httpcatalog.Source
	started bool
}

// brokerCatalog loads the destination catalog once per process, for the HTTP
// adapter and the PostgreSQL broker alike. AGENT_VAULT_CATALOG_VAULT_PATH
// (mount/path of a KV version 2 secret whose "catalog" field Terraform
// writes) is reloaded every 30 seconds without a restart; a version that
// fails validation is logged and the last good catalog stays in force.
// AGENT_VAULT_HTTP_CATALOG_FILE is a fixed catalog read at start.
func brokerCatalog(ctx context.Context, client *hashicorp.Client, getenv func(string) string, logger *slog.Logger) (*httpcatalog.Source, error) {
	sharedCatalog.Lock()
	defer sharedCatalog.Unlock()
	if sharedCatalog.started {
		return sharedCatalog.source, nil
	}
	// Test harnesses whose fixture database serves no TLS only.
	if v := getenv("AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES"); v == "1" || v == "true" {
		httpcatalog.PlaintextDatabases.Store(true)
		logger.Warn("broker catalog: plaintext database entries allowed (AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES); never set this outside a test harness")
	}
	var source *httpcatalog.Source
	if location := getenv("AGENT_VAULT_CATALOG_VAULT_PATH"); location != "" {
		mount, path, ok := strings.Cut(location, "/")
		if !ok || client == nil {
			return nil, fmt.Errorf("AGENT_VAULT_CATALOG_VAULT_PATH needs mount/path and a Vault client")
		}
		load := httpcatalog.VaultLoader(client.Logical(), mount, path, "catalog")
		var err error
		if source, err = httpcatalog.Open(ctx, load); err != nil {
			return nil, fmt.Errorf("broker catalog: %w", err)
		}
		// ctx is the server's lifetime context, so the watch runs until exit.
		go source.Watch(ctx, 30*time.Second, load, func(version int, err error) {
			logger.Error("broker catalog version rejected; keeping the last good catalog",
				slog.Int("version", version), slog.Int("in_force", source.Version()), slog.String("error", err.Error()))
		})
	} else if path := getenv("AGENT_VAULT_HTTP_CATALOG_FILE"); path != "" {
		catalog, err := httpcatalog.Load(path)
		if err != nil {
			return nil, err
		}
		source = httpcatalog.NewSource(catalog, 0)
	}
	sharedCatalog.source, sharedCatalog.started = source, true
	return source, nil
}

// httpHeaderAdapter builds the catalog-driven HTTP adapter when a broker
// catalog is configured. It requires the strict credential proxy, a Vault
// client and the signed audit chain, and refuses to start without any of
// them rather than serve unaudited or unlisted traffic.
func httpHeaderAdapter(ctx context.Context, srv *server.Server, getenv func(string) string) (*mitm.HeaderAdapter, error) {
	if getenv("AGENT_VAULT_CATALOG_VAULT_PATH") == "" && getenv("AGENT_VAULT_HTTP_CATALOG_FILE") == "" {
		return nil, nil
	}
	if !srv.CredentialProxyEnabled() {
		return nil, fmt.Errorf("requires AGENT_VAULT_CREDENTIAL_PROXY=true")
	}
	client := srv.HashicorpClient()
	if client == nil {
		if getenv("AGENT_VAULT_HTTP_CATALOG_FILE") != "" {
			if _, err := httpcatalog.Load(getenv("AGENT_VAULT_HTTP_CATALOG_FILE")); err != nil {
				return nil, err
			}
		}
		return nil, fmt.Errorf("requires a HashiCorp Vault client")
	}
	source, err := brokerCatalog(ctx, client, getenv, srv.Logger())
	if err != nil {
		return nil, err
	}
	chain, err := sharedAuditChain(ctx, client, srv.CleanupStore(), getenv, srv.Logger())
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, fmt.Errorf("requires AGENT_VAULT_AUDIT_CHAIN")
	}
	keys := &httpcatalog.Keys{Vault: client.Logical()}
	adapter := &mitm.HeaderAdapter{Catalog: source, Keys: keys, Audit: chain}
	adapter.BrowserTokens = &httpcatalog.Auth0Tokens{Keys: keys, Client: auth0Client(source, netguard.SafeDialContext(netguard.AllowPrivateFromEnv()))}
	githubEntries := false
	for _, e := range source.Current().Entries() {
		githubEntries = githubEntries || e.Kind == "git" || e.Kind == "github-api"
	}
	signer, err := githubAppSigner(client, getenv)
	switch {
	case err == nil:
		api := getenv("AGENT_VAULT_GITHUB_API_URL")
		if api != "" && !strings.HasPrefix(api, "https://") {
			return nil, fmt.Errorf("AGENT_VAULT_GITHUB_API_URL must be https")
		}
		minter := &githubapp.Minter{Signer: signer, API: api}
		adapter.GitTokens = minter
		// A catalog change that removes or narrows a repository revokes the
		// tokens it no longer grants instead of letting them run out.
		source.OnChange(func(c httpcatalog.Catalog) {
			minter.Prune(func(installation int64, repo string, p githubapp.Permissions) bool {
				return c.GitGranted(installation, repo, gitScope(p))
			})
		})
	case githubEntries:
		return nil, err
	}
	return adapter, nil
}

// auth0Client is how browser-session test users log in from the broker: over
// the same guarded dialer as every other upstream, to an Auth0 domain the
// current catalog names on port 443 and nowhere else, never following a
// redirect, since the login body holds the user's password and the client
// secret.
func auth0Client(catalog interface{ Current() httpcatalog.Catalog }, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	pinned := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port != "443" || !catalog.Current().HasAuth0Domain(host) {
			return nil, errors.New("auth0 login: host not in the catalog")
		}
		return dial(ctx, network, addr)
	}
	return &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{DialContext: pinned, TLSHandshakeTimeout: 5 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// gitScope names a token's permissions as the catalog grants them.
func gitScope(p githubapp.Permissions) string {
	switch {
	case p.PullRequests == "write":
		return "pull-requests"
	case p.Contents == "write":
		return "contents-write"
	default:
		return "contents-read"
	}
}

// githubAppSigner signs App JWTs with the App key imported into Transit, so
// the key never leaves Vault. AGENT_VAULT_GITHUB_APP_KV_PATH selects the
// fallback, a PEM on the gatehouse KV mount read into the broker per signature.
func githubAppSigner(client *hashicorp.Client, getenv func(string) string) (githubapp.JWTSigner, error) {
	if key := getenv("AGENT_VAULT_GITHUB_APP_TRANSIT_KEY"); key != "" {
		mount := getenv("AGENT_VAULT_GITHUB_APP_TRANSIT_MOUNT")
		if mount == "" {
			mount = "transit"
		}
		return githubapp.TransitSigner{Vault: client.Logical(), Mount: mount, Key: key}, nil
	}
	if path := getenv("AGENT_VAULT_GITHUB_APP_KV_PATH"); path != "" {
		return githubapp.KVSigner{Vault: client.Logical(), Mount: "gatehouse", Path: path, Field: "private_key"}, nil
	}
	return nil, fmt.Errorf("git catalog entries require AGENT_VAULT_GITHUB_APP_TRANSIT_KEY or AGENT_VAULT_GITHUB_APP_KV_PATH")
}

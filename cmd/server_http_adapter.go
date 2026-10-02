package cmd

import (
	"context"
	"fmt"

	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/server"
)

// httpHeaderAdapter builds the catalog-driven HTTP adapter when
// AGENT_VAULT_HTTP_CATALOG_FILE is set. It requires the strict credential
// proxy, a Vault client and the signed audit chain, and refuses to start
// without any of them rather than serve unaudited or unlisted traffic.
func httpHeaderAdapter(ctx context.Context, srv *server.Server, getenv func(string) string) (*mitm.HeaderAdapter, error) {
	path := getenv("AGENT_VAULT_HTTP_CATALOG_FILE")
	if path == "" {
		return nil, nil
	}
	if !srv.CredentialProxyEnabled() {
		return nil, fmt.Errorf("requires AGENT_VAULT_CREDENTIAL_PROXY=true")
	}
	catalog, err := httpcatalog.Load(path)
	if err != nil {
		return nil, err
	}
	client := srv.HashicorpClient()
	if client == nil {
		return nil, fmt.Errorf("requires a HashiCorp Vault client")
	}
	chain, err := sharedAuditChain(ctx, client, srv.CleanupStore(), getenv)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, fmt.Errorf("requires AGENT_VAULT_AUDIT_CHAIN")
	}
	adapter := &mitm.HeaderAdapter{Catalog: catalog, Keys: &httpcatalog.Keys{Vault: client.Logical()}, Audit: chain}
	for _, e := range catalog.Entries() {
		if e.Kind == "git" {
			signer, err := githubAppSigner(client, getenv)
			if err != nil {
				return nil, err
			}
			adapter.GitTokens = &githubapp.Minter{Signer: signer}
			break
		}
	}
	return adapter, nil
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

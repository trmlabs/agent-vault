package cmd

import (
	"context"
	"fmt"

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
	return &mitm.HeaderAdapter{Catalog: catalog, Keys: &httpcatalog.Keys{Vault: client.Logical()}, Audit: chain}, nil
}

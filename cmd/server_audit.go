package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/hashicorp"
)

const (
	auditCheckpointInterval = time.Minute
	auditKeyRefresh         = 5 * time.Minute
)

// brokerAuditChain starts the signed audit trail when AGENT_VAULT_AUDIT_CHAIN
// is set. Enabled with incomplete settings, an unreadable key or an unwritable
// stdout, it fails startup rather than serve unaudited.
func brokerAuditChain(ctx context.Context, client *hashicorp.Client, getenv func(string) string) (*auditchain.Chain, error) {
	if !boolEnvValue("AGENT_VAULT_AUDIT_CHAIN") {
		return nil, nil
	}
	setting := func(name, fallback string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return fallback
	}
	replica := getenv("AGENT_VAULT_AUDIT_REPLICA")
	if replica == "" {
		replica, _ = os.Hostname()
	}
	keys := auditchain.KVKeys{Mount: setting("AGENT_VAULT_AUDIT_HMAC_MOUNT", "secret"), Path: getenv("AGENT_VAULT_AUDIT_HMAC_PATH"), Field: setting("AGENT_VAULT_AUDIT_HMAC_FIELD", "key")}
	signer := auditchain.TransitSigner{Mount: setting("AGENT_VAULT_AUDIT_TRANSIT_MOUNT", "transit"), Key: getenv("AGENT_VAULT_AUDIT_TRANSIT_KEY")}
	if client == nil || keys.Path == "" || signer.Key == "" {
		return nil, fmt.Errorf("audit chain requires a Vault client, AGENT_VAULT_AUDIT_HMAC_PATH and AGENT_VAULT_AUDIT_TRANSIT_KEY")
	}
	keys.Vault, signer.Vault = client.Logical(), client.Logical()
	chain, err := auditchain.New(ctx, auditchain.Options{Out: os.Stdout, Replica: replica, Keys: keys, Signer: signer})
	if err != nil {
		return nil, err
	}
	// Sign a first checkpoint now so the chain is verifiable from boot. A
	// failure is recorded in the chain; Admit refuses once the grace passes.
	signCtx, cancel := context.WithTimeout(ctx, auditCheckpointInterval/2)
	_ = chain.Checkpoint(signCtx)
	cancel()
	go chain.Run(context.Background(), auditCheckpointInterval, auditKeyRefresh)
	return chain, nil
}

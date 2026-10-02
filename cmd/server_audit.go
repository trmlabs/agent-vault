package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/hashicorp"
)

const (
	auditCheckpointInterval = time.Minute
	auditKeyRefresh         = 5 * time.Minute
)

var sharedAudit struct {
	sync.Mutex
	chain   *auditchain.Chain
	started bool
}

// sharedAuditChain gives the PostgreSQL broker and the HTTP header adapter
// one chain per process, so a replica has a single sequence and boot.
func sharedAuditChain(ctx context.Context, client *hashicorp.Client, db any, getenv func(string) string, logger *slog.Logger) (*auditchain.Chain, error) {
	sharedAudit.Lock()
	defer sharedAudit.Unlock()
	if sharedAudit.started {
		return sharedAudit.chain, nil
	}
	chain, err := brokerAuditChain(ctx, client, db, getenv, logger)
	if err != nil {
		return nil, err
	}
	sharedAudit.chain, sharedAudit.started = chain, true
	return chain, nil
}

// brokerAuditChain starts the signed audit trail when AGENT_VAULT_AUDIT_CHAIN
// is set. Enabled with incomplete settings, an unreadable key or an unwritable
// stdout, it fails startup rather than serve unaudited. Off, it says so.
func brokerAuditChain(ctx context.Context, client *hashicorp.Client, db any, getenv func(string) string, logger *slog.Logger) (*auditchain.Chain, error) {
	if !boolEnvValue("AGENT_VAULT_AUDIT_CHAIN") {
		logger.Warn("pgproxy: signed audit trail is off (AGENT_VAULT_AUDIT_CHAIN unset); database sessions are not audited")
		return nil, nil
	}
	setting := func(name, fallback string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return fallback
	}
	// A stable name, such as a StatefulSet Pod name, lets each boot link to
	// the last and the store's head name the chain an export must reach.
	replica := getenv("AGENT_VAULT_AUDIT_REPLICA")
	if replica == "" {
		return nil, fmt.Errorf("audit chain requires AGENT_VAULT_AUDIT_REPLICA, a stable replica name such as the Pod name")
	}
	keys := auditchain.KVKeys{Mount: setting("AGENT_VAULT_AUDIT_HMAC_MOUNT", "gatehouse"), Path: getenv("AGENT_VAULT_AUDIT_HMAC_PATH"), Field: setting("AGENT_VAULT_AUDIT_HMAC_FIELD", "key")}
	signer := auditchain.TransitSigner{Mount: setting("AGENT_VAULT_AUDIT_TRANSIT_MOUNT", "transit"), Key: getenv("AGENT_VAULT_AUDIT_TRANSIT_KEY")}
	boots, ok := db.(auditchain.BootStore)
	if client == nil || !ok || keys.Path == "" || signer.Key == "" {
		return nil, fmt.Errorf("audit chain requires a Vault client, the SQL store, AGENT_VAULT_AUDIT_HMAC_PATH and AGENT_VAULT_AUDIT_TRANSIT_KEY")
	}
	keys.Vault, signer.Vault = client.Logical(), client.Logical()
	chain, err := auditchain.New(ctx, auditchain.Options{Out: os.Stdout, Replica: replica, Keys: keys, Signer: signer, Boots: boots})
	if err != nil {
		return nil, err
	}
	// Sign a first checkpoint now so the chain is verifiable from boot. A
	// failure is recorded in the chain; Admit refuses once the grace passes.
	signCtx, cancel := context.WithTimeout(ctx, auditCheckpointInterval/2)
	_ = chain.Checkpoint(signCtx)
	cancel()
	// The chain outlives the startup context; it runs for the process.
	go chain.Run(context.WithoutCancel(ctx), auditCheckpointInterval, auditKeyRefresh)
	return chain, nil
}

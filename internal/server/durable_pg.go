package server

import (
	"context"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

// NewDurableVaultLeaseMinter requires the SQL cleanup journal. Call Close after
// the PostgreSQL broker has stopped; a failed cleanup remains pending on disk.
// Owner IDs carry the replica name the audit chain uses, so operators can tell
// which broker holds a record.
func NewDurableVaultLeaseMinter(ctx context.Context, client *hashicorp.Client, st any) (*pgproxy.DurableLeaseMinter, error) {
	journal, ok := st.(pgproxy.CleanupJournal)
	if !ok {
		return nil, fmt.Errorf("PostgreSQL broker requires durable cleanup storage")
	}
	replica := os.Getenv("AGENT_VAULT_AUDIT_REPLICA")
	if replica == "" {
		replica, _ = os.Hostname()
	}
	return pgproxy.NewDurableLeaseMinter(ctx, client, journal, pgproxy.DurableLeaseOptions{Replica: replica})
}

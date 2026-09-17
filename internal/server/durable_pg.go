package server

import (
	"context"
	"fmt"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

// NewDurableVaultLeaseMinter requires the SQL cleanup journal. Call Close after
// the PostgreSQL broker has stopped; a failed cleanup remains pending on disk.
func NewDurableVaultLeaseMinter(ctx context.Context, client *hashicorp.Client, st any) (*pgproxy.DurableLeaseMinter, error) {
	journal, ok := st.(pgproxy.CleanupJournal)
	if !ok {
		return nil, fmt.Errorf("PostgreSQL broker requires durable cleanup storage")
	}
	return pgproxy.NewDurableLeaseMinter(ctx, client, journal, pgproxy.DurableLeaseOptions{})
}

package server

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
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
	replica := brokercore.ReplicaName(os.Getenv)
	if !brokercore.ValidReplicaName(replica) {
		return nil, fmt.Errorf("broker replica name must be a DNS-style name (set AGENT_VAULT_REPLICA from the Pod name)")
	}
	return pgproxy.NewDurableLeaseMinter(ctx, client, journal, pgproxy.DurableLeaseOptions{Replica: replica})
}

// brokerSessionStore is the store surface the fleet-wide session cap needs.
type brokerSessionStore interface {
	AddBrokerSession(ctx context.Context, owner, id, pod string, limit int) error
	RemoveBrokerSession(ctx context.Context, id string) error
}

// sessionLedger records live sessions under this replica's cleanup owner, so
// a dead replica's sessions stop counting when its owner row expires.
type sessionLedger struct {
	store brokerSessionStore
	owner func() string
}

// NewSessionLedger returns the fleet-wide per-Pod session ledger, or nil when
// the store cannot hold broker sessions (single-replica stores keep the
// in-memory cap only).
func NewSessionLedger(st any, minter *pgproxy.DurableLeaseMinter) pgproxy.SessionLedger {
	store, ok := st.(brokerSessionStore)
	if !ok || minter == nil {
		return nil
	}
	return sessionLedger{store: store, owner: minter.Owner}
}

func (l sessionLedger) Add(ctx context.Context, sessionID, workload string, limit int) error {
	err := l.store.AddBrokerSession(ctx, l.owner(), sessionID, workload, limit)
	if errors.Is(err, store.ErrPodSessionLimit) {
		return pgproxy.ErrSessionLimit
	}
	return err
}

func (l sessionLedger) Remove(ctx context.Context, sessionID string) error {
	return l.store.RemoveBrokerSession(ctx, sessionID)
}

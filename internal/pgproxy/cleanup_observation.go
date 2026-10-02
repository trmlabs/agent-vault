package pgproxy

import (
	"context"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

// CleanupSnapshot observes the dedicated broker after admission is withdrawn.
// It serializes with mint/reconciliation, checks the existing cleanup-owner
// heartbeat without extending it, and verifies the parent login. It never issues or revokes a lease.
// A consistent empty snapshot means broker reconciliation is idle, not proof
// that an external database has no residual role or session. New admission must
// remain withdrawn throughout the manager's handover, including after return.
func CleanupSnapshot(b *Broker, m *DurableLeaseMinter) runtimestatus.Snapshot {
	return func(ctx context.Context) (runtimestatus.Observation, error) {
		var result runtimestatus.Observation
		if b == nil || m == nil || m.ctx == nil || b.opts.Leases != m {
			return result, fmt.Errorf("cleanup observer unavailable")
		}
		if err := m.lock(ctx); err != nil {
			return result, err
		}
		defer m.mu.Unlock()
		if m.closed || m.ctx.Err() != nil {
			return result, fmt.Errorf("cleanup authority unavailable")
		}
		// An empty actor (unauthenticated connection, legacy record) is
		// unattributed and counts against every actor.
		attributed := make(map[runtimestatus.Attribution]runtimestatus.Counts)
		var unattributed runtimestatus.Counts
		tally := func(owner runtimestatus.Attribution, change func(*runtimestatus.Counts)) {
			if owner.ActorID == "" {
				change(&unattributed)
				return
			}
			counts := attributed[owner]
			change(&counts)
			attributed[owner] = counts
		}
		b.mu.Lock()
		before := b.connectionGeneration
		active := len(b.conns)
		for conn := range b.conns {
			tally(b.connActors[conn], func(c *runtimestatus.Counts) { c.ActiveConnections++ })
		}
		closed := b.closed
		b.mu.Unlock()
		if closed || !b.IsListening() {
			return result, fmt.Errorf("database broker unavailable")
		}
		if err := m.client.CheckAuthorization(ctx); err != nil {
			return result, err
		}
		records, err := m.journal.ListDatabaseCleanup(ctx)
		if err != nil {
			return result, err
		}
		m.activeMu.Lock()
		activeLeases := len(m.active)
		m.activeMu.Unlock()
		if activeLeases > len(records) {
			return result, fmt.Errorf("cleanup journal inconsistent")
		}
		unknown := 0
		for _, record := range records {
			known := record.LeaseID != ""
			if !known {
				unknown++
			}
			tally(runtimestatus.Attribution{ActorID: record.ActorID, WorkloadID: record.WorkloadID}, func(c *runtimestatus.Counts) {
				c.UnfinishedCleanup++
				if !known {
					c.UnknownCleanup++
				}
			})
		}
		if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner, time.Now()); err != nil {
			return result, err
		}
		b.mu.Lock()
		consistent := before == b.connectionGeneration && !b.closed && b.IsListening()
		b.mu.Unlock()
		if ctx.Err() != nil || m.ctx.Err() != nil {
			return result, fmt.Errorf("cleanup authority unavailable")
		}
		return runtimestatus.Observation{Initialized: true, Healthy: true, Consistent: consistent, ActiveConnections: active, UnfinishedCleanup: len(records), UnknownCleanup: unknown,
			Attributed: attributed, Unattributed: unattributed}, nil
	}
}

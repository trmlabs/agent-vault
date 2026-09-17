package pgproxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

type CleanupJournal interface {
	ClaimDatabaseCleanupOwner(context.Context, string, time.Time, time.Time) error
	RenewDatabaseCleanupOwner(context.Context, string, time.Time, time.Time) error
	ReleaseDatabaseCleanupOwner(context.Context, string) error
	AddDatabaseCleanup(context.Context, string, store.DatabaseCleanup) error
	SetDatabaseCleanupLease(context.Context, string, string, string) error
	ListDatabaseCleanup(context.Context) ([]store.DatabaseCleanup, error)
	DeleteDatabaseCleanup(context.Context, string) error
	ConfirmDatabaseCleanup(context.Context, string, string, string) error
}

type DurableLeaseOptions struct {
	TokenTTL      time.Duration
	RetryInterval time.Duration
	OwnerTTL      time.Duration
}

type durableLease struct {
	accessor string
	expires  time.Time
}

// DurableLeaseMinter journals a child-token accessor before credential issuance.
// Known leases are reconciled automatically. An interrupted response without a
// lease ID keeps its binding quarantined for explicit operator reconciliation.
// Only one broker may own the journal; this is not a multi-replica lease manager.
type DurableLeaseMinter struct {
	client   *hashicorp.Client
	journal  CleanupJournal
	opts     DurableLeaseOptions
	owner    string
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	activeMu sync.Mutex
	active   map[string]durableLease
	closed   bool
	closeErr error
}

func NewDurableLeaseMinter(ctx context.Context, client *hashicorp.Client, journal CleanupJournal, opts DurableLeaseOptions) (*DurableLeaseMinter, error) {
	if client == nil || journal == nil {
		return nil, fmt.Errorf("database cleanup requires Vault and durable storage")
	}
	if opts.TokenTTL <= 0 {
		opts.TokenTTL = time.Hour
	}
	if opts.RetryInterval <= 0 {
		opts.RetryInterval = time.Second
	}
	if opts.OwnerTTL <= 0 {
		opts.OwnerTTL = 30 * time.Second
	}
	if opts.OwnerTTL < 3*time.Second || opts.TokenTTL < time.Second || opts.TokenTTL > 24*time.Hour {
		return nil, fmt.Errorf("invalid database lifecycle timing")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	m := &DurableLeaseMinter{client: client, journal: journal, opts: opts, owner: fmt.Sprintf("%x", random), done: make(chan struct{}), active: make(map[string]durableLease)}
	m.ctx, m.cancel = context.WithCancel(ctx)
	now := time.Now()
	if err := journal.ClaimDatabaseCleanupOwner(ctx, m.owner, now, now.Add(opts.OwnerTTL)); err != nil {
		m.cancel()
		return nil, err
	}
	go m.run()
	return m, nil
}

func (m *DurableLeaseMinter) AuthorityDone() <-chan struct{} { return m.ctx.Done() }

func (m *DurableLeaseMinter) lock(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ConfirmDatabaseCleanup serializes operator attestation with issuance and
// reconciliation. A response that arrived while the operator was investigating
// must remain a known lease, never an acknowledged unknown issuance.
func (m *DurableLeaseMinter) ConfirmDatabaseCleanup(ctx context.Context, accessor, evidence string) error {
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil || m.closed {
		return fmt.Errorf("database cleanup authority unavailable")
	}
	now := time.Now()
	if err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, now, now.Add(m.opts.OwnerTTL)); err != nil {
		return fmt.Errorf("database cleanup authority unavailable")
	}
	records, err := m.journal.ListDatabaseCleanup(ctx)
	if err != nil {
		return err
	}
	unknown := false
	for _, record := range records {
		if record.Accessor == accessor {
			unknown = record.LeaseID == ""
			break
		}
	}
	if !unknown {
		return fmt.Errorf("unknown-issuance record not found")
	}
	if err := m.client.RevokeDatabaseSession(ctx, accessor); err != nil {
		return err
	}
	return m.journal.ConfirmDatabaseCleanup(ctx, m.owner, accessor, evidence)
}

func (m *DurableLeaseMinter) run() {
	defer close(m.done)
	heartbeat := time.NewTicker(m.opts.OwnerTTL / 3)
	defer heartbeat.Stop()
	retry := time.NewTicker(m.opts.RetryInterval)
	defer retry.Stop()
	// Heartbeats must continue while a failed external cleanup is timing out.
	var cleanup sync.WaitGroup
	defer cleanup.Wait()
	busy := make(chan struct{}, 1)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-heartbeat.C:
			ctx, cancel := context.WithTimeout(m.ctx, m.opts.OwnerTTL/3)
			now := time.Now()
			err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, now, now.Add(m.opts.OwnerTTL))
			cancel()
			if err != nil {
				m.cancel()
				return
			}
		case <-retry.C:
			select {
			case busy <- struct{}{}:
				cleanup.Add(1)
				go func() {
					defer cleanup.Done()
					defer func() { <-busy }()
					if !m.mu.TryLock() {
						return
					}
					defer m.mu.Unlock()
					ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
					defer cancel()
					_ = m.reconcile(ctx, "")
				}()
			default:
			}
		}
	}
}

func databaseBinding(vaultID string, svc *DatabaseService) string {
	// A reconfigured binding retains its identity so unresolved old credentials
	// prevent reopening the same service under a different mount or role.
	return vaultID + "/" + svc.Name
}

func (m *DurableLeaseMinter) reconcile(ctx context.Context, binding string) error {
	now := time.Now()
	if err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, now, now.Add(m.opts.OwnerTTL)); err != nil {
		return err
	}
	records, err := m.journal.ListDatabaseCleanup(ctx)
	if err != nil {
		return err
	}
	m.activeMu.Lock()
	active := make(map[string]bool, len(m.active))
	for _, lease := range m.active {
		active[lease.accessor] = true
	}
	m.activeMu.Unlock()
	var failure error
	for _, record := range records {
		if active[record.Accessor] || (binding != "" && binding != record.Binding) {
			continue
		}
		now := time.Now()
		if err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, now, now.Add(m.opts.OwnerTTL)); err != nil {
			return err
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, leaseRevokeTimeout)
		var err error
		if record.LeaseID == "" {
			_ = m.client.RevokeDatabaseSession(cleanupCtx, record.Accessor)
			err = fmt.Errorf("unknown database issuance requires operator reconciliation")
		} else {
			err = m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, record.LeaseID)
			if err == nil {
				err = m.client.RevokeDatabaseSession(cleanupCtx, record.Accessor)
			}
		}
		cancel()
		if err == nil {
			err = m.journal.DeleteDatabaseCleanup(ctx, record.Accessor)
		}
		if err != nil {
			failure = fmt.Errorf("database binding cleanup incomplete: %w", err)
		}
	}
	return failure
}

func (m *DurableLeaseMinter) Mint(ctx context.Context, vaultID string, svc *DatabaseService) (*Lease, error) {
	if svc == nil || vaultID == "" || svc.Name == "" {
		return nil, fmt.Errorf("database binding is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	if err := m.lock(ctx); err != nil {
		return nil, err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, fmt.Errorf("database cleanup authority unavailable")
	}
	binding := databaseBinding(vaultID, svc)
	if err := m.reconcile(ctx, binding); err != nil {
		return nil, err
	}
	session, err := m.client.NewDatabaseSession(ctx, svc.Mount, svc.Role, m.opts.TokenTTL)
	if err != nil {
		return nil, err
	}
	record := store.DatabaseCleanup{Accessor: session.Accessor, Binding: binding}
	if err := m.journal.AddDatabaseCleanup(ctx, m.owner, record); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = m.client.RevokeDatabaseSession(cleanupCtx, session.Accessor)
		return nil, fmt.Errorf("persist database cleanup before issuance: %w", err)
	}
	issued := time.Now()
	credential, err := session.ReadCredential(ctx)
	if err != nil {
		// Keep the durable accessor even if immediate cleanup fails. A missing
		// credential response leaves the binding quarantined until database-backed
		// reconciliation confirms that no issued role or session remains.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = m.reconcile(cleanupCtx, binding)
		return nil, err
	}
	if err := m.journal.SetDatabaseCleanupLease(ctx, m.owner, session.Accessor, credential.LeaseID); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, credential.LeaseID)
		_ = m.client.RevokeDatabaseSession(cleanupCtx, session.Accessor)
		return nil, fmt.Errorf("persist issued database lease: %w", err)
	}
	expiry := credential.ExpiresAt(issued)
	if expiry.After(session.ExpiresAt) {
		expiry = session.ExpiresAt
	}
	m.activeMu.Lock()
	m.active[credential.LeaseID] = durableLease{accessor: session.Accessor, expires: session.ExpiresAt}
	m.activeMu.Unlock()
	return &Lease{ID: credential.LeaseID, Username: credential.Username, Password: credential.Password, ExpiresAt: expiry, Renewable: credential.Renewable}, nil
}

func (m *DurableLeaseMinter) Renew(ctx context.Context, id string, increment time.Duration) (time.Time, error) {
	m.activeMu.Lock()
	lease, ok := m.active[id]
	m.activeMu.Unlock()
	if !ok || m.ctx.Err() != nil || !time.Now().Before(lease.expires) {
		return time.Time{}, fmt.Errorf("database session unavailable")
	}
	started := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	ttl, err := m.client.RenewLease(ctx, id, increment)
	if err != nil {
		return time.Time{}, err
	}
	expiry := started.Add(ttl)
	if expiry.After(lease.expires) {
		expiry = lease.expires
	}
	return expiry, nil
}

func (m *DurableLeaseMinter) Revoke(ctx context.Context, id string) error {
	m.activeMu.Lock()
	lease, ok := m.active[id]
	if !ok {
		m.activeMu.Unlock()
		return fmt.Errorf("database session is not active")
	}
	delete(m.active, id)
	m.activeMu.Unlock()
	// Retirement cannot wait for external cleanup: even a timed-out caller must
	// leave this durable record visible to reconciliation and binding admission.
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if err := m.client.RevokeDatabaseLeaseConfirmed(ctx, id); err != nil {
		return err
	}
	if err := m.client.RevokeDatabaseSession(ctx, lease.accessor); err != nil {
		return err
	}
	return m.journal.DeleteDatabaseCleanup(ctx, lease.accessor)
}

// Close runs after the broker stops sessions. Failed records remain durable for
// the next owner. Caller context bounds waiting and all shutdown cleanup.
func (m *DurableLeaseMinter) Close(ctx context.Context) error {
	m.cancel()
	select {
	case <-m.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if m.closed {
		return m.closeErr
	}
	m.closed = true
	m.activeMu.Lock()
	m.active = make(map[string]durableLease)
	m.activeMu.Unlock()
	err := m.reconcile(ctx, "")
	if releaseErr := m.journal.ReleaseDatabaseCleanupOwner(ctx, m.owner); err == nil {
		err = releaseErr
	}
	m.closeErr = err
	return err
}

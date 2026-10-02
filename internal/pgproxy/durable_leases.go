package pgproxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// CleanupJournal is the store's per-replica cleanup journal. Owner expiry is
// written and compared by the database clock inside these methods.
type CleanupJournal interface {
	CheckDatabaseCleanupOwner(context.Context, string) error
	ClaimDatabaseCleanupOwner(context.Context, string, time.Duration) error
	RenewDatabaseCleanupOwner(context.Context, string, time.Duration) error
	ReleaseDatabaseCleanupOwner(context.Context, string) error
	ClaimOrphanedDatabaseCleanup(context.Context, string) (int, error)
	LiveDatabaseCleanupOwners(context.Context) (int, error)
	AddDatabaseCleanup(context.Context, string, store.DatabaseCleanup) error
	SetDatabaseCleanupLease(context.Context, string, string, string) error
	QuarantineDatabaseCleanup(context.Context, string, string) error
	DatabaseBindingQuarantined(context.Context, string) (bool, error)
	ListDatabaseCleanup(context.Context) ([]store.DatabaseCleanup, error)
	ListOwnedDatabaseCleanup(context.Context, string) ([]store.DatabaseCleanup, error)
	DeleteDatabaseCleanup(context.Context, string) error
	ConfirmDatabaseCleanup(context.Context, string, string, string) error
}

type DurableLeaseOptions struct {
	TokenTTL      time.Duration
	RetryInterval time.Duration
	// OwnerTTL is the takeover delay: survivors may claim this replica's
	// records once this long has passed, by the database clock, since its last
	// renewal. Default 30s.
	OwnerTTL time.Duration
	// FenceAfter stops this replica when no renewal has succeeded for this long
	// since the renewal was sent. It is shorter than OwnerTTL, so sessions are
	// closed before any survivor can claim. Default two thirds of OwnerTTL.
	FenceAfter time.Duration
	// Heartbeat is the renewal interval. Default one sixth of OwnerTTL.
	Heartbeat time.Duration
	// Replica names the broker in owner IDs, for operators. Each process adds a
	// random suffix, so a restarted Pod never inherits its predecessor's records.
	Replica string
}

type durableLease struct {
	accessor string
	expires  time.Time
}

// DurableLeaseMinter journals a child-token accessor before credential issuance.
// Known leases are reconciled automatically. An interrupted response without a
// lease ID quarantines its binding fleet-wide for explicit operator
// reconciliation. Each replica owns the records it wrote; a survivor claims a
// dead replica's records and revokes them. A replica that cannot renew fences
// itself before its records become claimable.
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

	renewMu   sync.Mutex
	lastRenew time.Time // send time of the last successful renewal
	fenced    atomic.Bool
	ready     atomic.Bool
	live      atomic.Int64
	kick      chan struct{}
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
	if opts.FenceAfter <= 0 {
		opts.FenceAfter = opts.OwnerTTL * 2 / 3
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = opts.OwnerTTL / 6
	}
	if opts.OwnerTTL < 3*time.Second || opts.TokenTTL < time.Second || opts.TokenTTL > 24*time.Hour ||
		opts.Heartbeat >= opts.FenceAfter || opts.FenceAfter >= opts.OwnerTTL {
		return nil, fmt.Errorf("invalid database lifecycle timing")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	owner := fmt.Sprintf("%x", random)
	if opts.Replica != "" {
		owner = opts.Replica + "/" + owner
	}
	m := &DurableLeaseMinter{client: client, journal: journal, opts: opts, owner: owner, done: make(chan struct{}), active: make(map[string]durableLease), kick: make(chan struct{}, 1)}
	m.ctx, m.cancel = context.WithCancel(ctx)
	sent := time.Now()
	if err := journal.ClaimDatabaseCleanupOwner(ctx, m.owner, opts.OwnerTTL); err != nil {
		m.cancel()
		return nil, err
	}
	m.lastRenew = sent
	m.live.Store(1)
	if n, err := journal.LiveDatabaseCleanupOwners(ctx); err == nil && n > 0 {
		m.live.Store(int64(n))
	}
	// A restart takes over expired predecessors at once rather than a heartbeat later.
	if claimed, err := journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner); err == nil && claimed > 0 {
		m.kick <- struct{}{}
	}
	go m.run()
	return m, nil
}

// AuthorityDone closes when this replica fences itself or closes. The broker
// then stops accepting and closes every session.
func (m *DurableLeaseMinter) AuthorityDone() <-chan struct{} { return m.ctx.Done() }

// Fenced reports that this replica lost or could not renew its owner row.
func (m *DurableLeaseMinter) Fenced() bool { return m.fenced.Load() }

// Ready reports one renewal after start and no fence. Waiting one heartbeat
// lets the other replicas count this one and shrink their budgets first.
func (m *DurableLeaseMinter) Ready() bool {
	return m.ready.Load() && m.ctx.Err() == nil && m.untilFence(time.Now()) > 0
}

// LiveReplicas is the number of live owner rows at the last heartbeat,
// including this replica.
func (m *DurableLeaseMinter) LiveReplicas() int { return int(max(1, m.live.Load())) }

// untilFence is the time left before this replica must stop. It counts both
// monotonic and wall time since the last renewal was sent: the monotonic clock
// can stop while a host is suspended, and the larger reading wins.
func (m *DurableLeaseMinter) untilFence(now time.Time) time.Duration {
	m.renewMu.Lock()
	last := m.lastRenew
	m.renewMu.Unlock()
	elapsed := max(now.Sub(last), now.Round(0).Sub(last.Round(0)))
	return m.opts.FenceAfter - elapsed
}

func (m *DurableLeaseMinter) fence() {
	m.fenced.Store(true)
	m.cancel()
}

// heartbeat renews the owner row, then claims orphaned records. It returns
// false when this replica must fence: ownership is lost, or the fence deadline
// passed. A failed renewal is retried on the next tick until the deadline.
func (m *DurableLeaseMinter) heartbeat() bool {
	sent := time.Now()
	remaining := m.untilFence(sent)
	if remaining <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(m.ctx, min(m.opts.Heartbeat, remaining))
	defer cancel()
	err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, m.opts.OwnerTTL)
	if errors.Is(err, store.ErrDatabaseCleanupOwnershipLost) {
		return false
	}
	if err != nil {
		return m.untilFence(time.Now()) > 0
	}
	m.renewMu.Lock()
	m.lastRenew = sent
	m.renewMu.Unlock()
	m.ready.Store(true)
	if n, err := m.journal.LiveDatabaseCleanupOwners(ctx); err == nil && n > 0 {
		m.live.Store(int64(n))
	}
	if claimed, err := m.journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner); err == nil && claimed > 0 {
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
	return true
}

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
	if m.ctx.Err() != nil || m.closed || m.untilFence(time.Now()) <= 0 {
		return fmt.Errorf("database cleanup authority unavailable")
	}
	if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
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
	heartbeat := time.NewTicker(m.opts.Heartbeat)
	defer heartbeat.Stop()
	retry := time.NewTicker(m.opts.RetryInterval)
	defer retry.Stop()
	fence := time.NewTimer(m.untilFence(time.Now()))
	defer fence.Stop()
	// Heartbeats must continue while a failed external cleanup is timing out.
	var cleanup sync.WaitGroup
	defer cleanup.Wait()
	busy := make(chan struct{}, 1)
	for {
		reconcile := false
		select {
		case <-m.ctx.Done():
			return
		case <-fence.C:
			m.fence()
			return
		case <-heartbeat.C:
			if !m.heartbeat() {
				m.fence()
				return
			}
			fence.Reset(m.untilFence(time.Now()))
		case <-retry.C:
			reconcile = true
		case <-m.kick:
			reconcile = true
		}
		if reconcile {
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

// reconcile revokes this replica's records that no live session holds,
// including records claimed from dead replicas. Revocation is idempotent, so a
// record revoked twice after a contested takeover is harmless.
func (m *DurableLeaseMinter) reconcile(ctx context.Context, binding string) error {
	if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
		return err
	}
	records, err := m.journal.ListOwnedDatabaseCleanup(ctx, m.owner)
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
		if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
			return err
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, leaseRevokeTimeout)
		var err error
		if record.LeaseID == "" {
			_ = m.client.RevokeDatabaseSession(cleanupCtx, record.Accessor)
			_ = m.journal.QuarantineDatabaseCleanup(cleanupCtx, m.owner, record.Accessor)
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
	if failure == nil && binding != "" {
		// Another replica's unresolved issuance holds the binding too.
		if quarantined, err := m.journal.DatabaseBindingQuarantined(ctx, binding); err != nil || quarantined {
			failure = fmt.Errorf("database binding cleanup incomplete: unknown issuance requires operator reconciliation")
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
	if m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 {
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
	if !ok || m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 || !time.Now().Before(lease.expires) {
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

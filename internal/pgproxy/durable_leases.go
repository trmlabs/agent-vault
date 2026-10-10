package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	MarkDatabaseCleanupTokenRevoked(context.Context, string, string) error
	SettledDatabaseCleanup(context.Context, string, time.Duration) ([]store.DatabaseCleanup, error)
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
	// Logger names a refused start or a duplicate-name fence. Default discard.
	Logger *slog.Logger
	// IssueTimeout bounds one issuance from child token to journaled lease.
	// Neither its caller leaving nor a graceful Close cuts it short, only this
	// bound or a fence: abandoned between the credential read and the lease
	// write, it would leave an unknown issuance. Default 15s, the handshake's.
	IssueTimeout time.Duration
	// UnknownSettle is how long an unknown issuance's child token must have
	// been dead, by the database clock, before Vault's lease list is read to
	// clear it. It must exceed Vault's max_request_duration (90s by default)
	// plus clock skew, so no request made with the token can still register a
	// lease. Default 3 minutes.
	UnknownSettle time.Duration
	// UnknownRecheck spaces automatic checks of one unknown issuance that
	// could not be cleared. Default 30s.
	UnknownRecheck time.Duration
}

type durableLease struct {
	accessor string
	expires  time.Time
	session  *hashicorp.DatabaseSession // revokes itself while this process holds it
}

// DurableLeaseMinter journals a child-token accessor before credential issuance.
// Known leases are reconciled automatically. An interrupted response without a
// lease ID quarantines its binding fleet-wide until Vault's lease list proves
// no credential from it remains (clearUnknown) or an operator reconciles it.
// Each replica owns the records it wrote; a survivor claims a dead replica's
// records and revokes them. A replica that cannot renew fences itself before
// its records become claimable.
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

	releaseOnce sync.Once
	releaseErr  error

	renewMu   sync.Mutex
	lastRenew time.Time // send time of the last successful renewal
	fenced    atomic.Bool
	live      atomic.Int64
	kick      chan struct{}

	draining atomic.Bool          // Close has begun: no new issuance starts
	checked  map[string]time.Time // last automatic check per unknown issuance; under mu
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
	if opts.IssueTimeout <= 0 {
		opts.IssueTimeout = defaultHandshakeTimeout
	}
	if opts.UnknownSettle <= 0 {
		opts.UnknownSettle = 3 * time.Minute
	}
	if opts.UnknownRecheck <= 0 {
		opts.UnknownRecheck = 30 * time.Second
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
	m := &DurableLeaseMinter{client: client, journal: journal, opts: opts, owner: owner, done: make(chan struct{}), active: make(map[string]durableLease), kick: make(chan struct{}, 1), checked: make(map[string]time.Time)}
	m.ctx, m.cancel = context.WithCancel(ctx)
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		m.opts.Logger = opts.Logger
	}
	sent, err := claimOwner(ctx, journal, m.owner, opts)
	if err != nil {
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

// claimOwner registers this process. Another process under the same replica
// name may be a crashed predecessor whose row has not expired yet, so the
// claim is retried until a row that stopped renewing would have expired; a
// name still held after that belongs to a live process, and this one refuses
// to start.
func claimOwner(ctx context.Context, journal CleanupJournal, owner string, opts DurableLeaseOptions) (time.Time, error) {
	deadline := time.Now().Add(opts.OwnerTTL + opts.Heartbeat)
	for {
		sent := time.Now()
		err := journal.ClaimDatabaseCleanupOwner(ctx, owner, opts.OwnerTTL)
		if !errors.Is(err, store.ErrReplicaNameInUse) {
			return sent, err
		}
		if time.Now().After(deadline) {
			opts.Logger.Error("pgproxy: replica name held by another live broker; refusing to start", slog.String("replica", opts.Replica))
			return time.Time{}, fmt.Errorf("%w: replica %q (each broker needs its own AGENT_VAULT_REPLICA)", store.ErrReplicaNameInUse, opts.Replica)
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(opts.Heartbeat):
		}
	}
}

// AuthorityDone closes when this replica fences itself or closes. The broker
// then stops accepting and closes every session.
func (m *DurableLeaseMinter) AuthorityDone() <-chan struct{} { return m.ctx.Done() }

// Owner is this process's owner ID in the journal, for session rows.
func (m *DurableLeaseMinter) Owner() string { return m.owner }

// Fenced reports that this replica lost or could not renew its owner row.
func (m *DurableLeaseMinter) Fenced() bool { return m.fenced.Load() }

// Ready reports a fresh owner row: claimed at start or renewed within half the
// fence deadline. A restarted process is ready only once it holds its own new
// row, and a replica whose renewals are failing stops taking new sessions
// before it fences.
func (m *DurableLeaseMinter) Ready() bool {
	return !m.fenced.Load() && !m.draining.Load() && m.ctx.Err() == nil && m.untilFence(time.Now()) > m.opts.FenceAfter/2
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
	if errors.Is(err, store.ErrReplicaNameInUse) {
		m.opts.Logger.Error("pgproxy: replica name held by another live broker; fencing", slog.String("replica", m.opts.Replica))
		return false
	}
	if errors.Is(err, store.ErrDatabaseCleanupOwnershipLost) {
		return false
	}
	if err != nil {
		return m.untilFence(time.Now()) > 0
	}
	m.renewMu.Lock()
	m.lastRenew = sent
	m.renewMu.Unlock()
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
	// The record's child token is not revoked here: its value died with the
	// process that held it, and it expires within its TTL, revoking any lease
	// it issued. The operator's database evidence is what reopens the binding.
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
					// Claim on every pass, not only on heartbeats, so a dead
					// replica's records move within a second of its expiry.
					if m.untilFence(time.Now()) > 0 {
						_, _ = m.journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner)
					}
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
		if record.LeaseID == "" && m.clearUnknown(ctx, record) {
			continue
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, leaseRevokeTimeout)
		var err error
		// A record no live session holds belongs to a dead or retired session:
		// its credential is revoked by path. Its child token is not revoked by
		// accessor, a right no policy could limit to the broker's own tokens;
		// only that session's process ever held the token, and it expires
		// within its TTL.
		if record.LeaseID == "" {
			_ = m.journal.QuarantineDatabaseCleanup(cleanupCtx, m.owner, record.Accessor)
			err = fmt.Errorf("unknown database issuance requires operator reconciliation")
		} else {
			err = m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, record.LeaseID)
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

// clearUnknown clears an unknown issuance without an operator when Vault shows
// that no credential from it can remain:
//
//  1. its child token has been dead, revoked by this process or past its
//     maximum lifetime, for UnknownSettle by the database clock, so no request
//     made with it can still register a lease; and
//  2. Vault's lease list for the record's credential path, read after that,
//     holds no lease the fleet's journal does not account for.
//
// Vault deletes a lease only after the database engine has removed its user,
// and keeps a failing or irrevocable revocation listed, so a credential from
// this issuance that still exists would be listed and unaccounted. Vault
// returns a credential only after registering its lease, so one that was never
// registered was never handed to anyone. Token revocation success alone proves
// nothing (Vault queues lease revocation) and neither does elapsed lifetime;
// both only decide when the list is worth reading. Anything short of the
// proof stays quarantined for the operator procedure: a record without its
// mount and role, a refused or unrecognized list, or any unaccounted lease,
// including another consumer's on a shared role. Requires m.mu.
func (m *DurableLeaseMinter) clearUnknown(ctx context.Context, record store.DatabaseCleanup) bool {
	if m.closed || record.Mount == "" || record.Role == "" {
		return false
	}
	now := time.Now()
	if last, ok := m.checked[record.Accessor]; ok && now.Sub(last) < m.opts.UnknownRecheck {
		return false
	}
	settled, err := m.journal.SettledDatabaseCleanup(ctx, m.owner, m.opts.UnknownSettle)
	if err != nil {
		return false
	}
	ready := false
	for _, candidate := range settled {
		ready = ready || candidate.Accessor == record.Accessor && candidate.Mount == record.Mount && candidate.Role == record.Role
	}
	if !ready {
		return false
	}
	m.checked[record.Accessor] = now
	log := m.opts.Logger.With(slog.String("binding", record.Binding))
	// The list comes before the journal read: a lease issued meanwhile by a
	// live session is then either journaled or still unaccounted.
	leases, err := m.client.ListDatabaseLeases(ctx, record.Mount, record.Role)
	if err != nil {
		log.Warn("pgproxy: unknown database issuance kept for the operator: Vault lease list unavailable", slog.String("error", err.Error()))
		return false
	}
	fleet, err := m.journal.ListDatabaseCleanup(ctx)
	if err != nil {
		return false
	}
	known := make(map[string]bool, len(fleet))
	for _, other := range fleet {
		if other.LeaseID != "" {
			known[other.LeaseID] = true
		}
	}
	unaccounted := 0
	for _, lease := range leases {
		if !known[lease] {
			unaccounted++
		}
	}
	prefix, _ := hashicorp.DatabaseLeasePrefix(record.Mount, record.Role)
	if unaccounted > 0 {
		log.Warn("pgproxy: unknown database issuance kept for the operator: Vault holds leases the journal does not account for",
			slog.String("lease_prefix", prefix), slog.Int("unaccounted", unaccounted))
		return false
	}
	evidence, _ := json.Marshal(map[string]any{
		"verification": "automated_vault_lease_absence", "checked_at": now.UTC().Format(time.RFC3339Nano),
		"lease_prefix": prefix, "listed_leases": len(leases), "settle_seconds": int(m.opts.UnknownSettle / time.Second),
	})
	if err := m.journal.ConfirmDatabaseCleanup(ctx, m.owner, record.Accessor, string(evidence)); err != nil {
		return false
	}
	delete(m.checked, record.Accessor)
	log.Info("pgproxy: unknown database issuance cleared: Vault holds no unaccounted lease for it", slog.String("lease_prefix", prefix))
	return true
}

// errDraining refuses an issuance once Close has begun.
var errDraining = errors.New("database broker is stopping")

func (m *DurableLeaseMinter) Mint(ctx context.Context, scope AgentScope, svc *DatabaseService) (*Lease, error) {
	if svc == nil || scope.VaultID == "" || svc.Name == "" {
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
	if m.draining.Load() {
		return nil, errDraining
	}
	if m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 {
		return nil, fmt.Errorf("database cleanup authority unavailable")
	}
	binding := databaseBinding(scope.VaultID, svc)
	if err := m.reconcile(ctx, binding); err != nil {
		return nil, err
	}
	return m.issue(ctx, scope, svc, binding)
}

// issue runs one issuance, from child token to journaled lease, under its own
// deadline. A caller that leaves partway, or a graceful Close, does not cut it
// short: stopped between the credential read and the lease write, it would
// leave an unknown issuance that closes the binding for everyone. Only
// IssueTimeout or a fence ends it early. If the caller left in the meantime,
// the credential it no longer wants is revoked here. Requires m.mu.
func (m *DurableLeaseMinter) issue(caller context.Context, scope AgentScope, svc *DatabaseService, binding string) (*Lease, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), m.opts.IssueTimeout)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	session, err := m.client.NewDatabaseSession(ctx, svc.Mount, svc.Role, m.opts.TokenTTL)
	if err != nil {
		return nil, err
	}
	record := store.DatabaseCleanup{Accessor: session.Accessor, Binding: binding, ActorID: scope.ActorID, WorkloadID: scope.WorkloadID,
		Mount: svc.Mount, Role: svc.Role, TokenTTL: m.opts.TokenTTL}
	if err := m.journal.AddDatabaseCleanup(ctx, m.owner, record); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = session.Revoke(cleanupCtx)
		return nil, fmt.Errorf("persist database cleanup before issuance: %w", err)
	}
	issued := time.Now()
	credential, err := session.ReadCredential(ctx)
	if err != nil {
		// Vault may have issued a credential whose response was lost. This
		// process still holds the child token, and revoking it with its own
		// token revokes every lease it issued, that one included. The durable
		// record stays, so the binding is quarantined until Vault's lease list
		// or an operator shows that no issued credential remains. A confirmed
		// revocation starts the settle wait now rather than at token expiry.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		if session.Revoke(cleanupCtx) == nil {
			_ = m.journal.MarkDatabaseCleanupTokenRevoked(cleanupCtx, m.owner, session.Accessor)
		}
		_ = m.reconcile(cleanupCtx, binding)
		return nil, err
	}
	if err := m.journal.SetDatabaseCleanupLease(ctx, m.owner, session.Accessor, credential.LeaseID); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, credential.LeaseID)
		_ = session.Revoke(cleanupCtx)
		return nil, fmt.Errorf("persist issued database lease: %w", err)
	}
	if err := caller.Err(); err != nil {
		// The lease is journaled, so a failed revoke here is retried by path.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		if m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, credential.LeaseID) == nil {
			_ = session.Revoke(cleanupCtx)
			_ = m.journal.DeleteDatabaseCleanup(cleanupCtx, session.Accessor)
		}
		return nil, err
	}
	expiry := credential.ExpiresAt(issued)
	if expiry.After(session.ExpiresAt) {
		expiry = session.ExpiresAt
	}
	m.activeMu.Lock()
	m.active[credential.LeaseID] = durableLease{accessor: session.Accessor, expires: session.ExpiresAt, session: session}
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
	// The credential is gone; ending the child token is tidiness, not a
	// condition for clearing the record (see DatabaseSession.Revoke).
	if lease.session != nil {
		_ = lease.session.Revoke(ctx)
	}
	return m.journal.DeleteDatabaseCleanup(ctx, lease.accessor)
}

// Close runs after the broker stops sessions. Failed records remain durable for
// the next owner. Caller context bounds waiting and all shutdown cleanup.
// However that goes, the owner row is released last, on its own short
// deadline, so a planned restart under the same replica name registers at
// once instead of waiting out the row; records still held become claimable.
func (m *DurableLeaseMinter) Close(ctx context.Context) error {
	defer func() { _ = m.release() }()
	// Drain: no new issuance starts, and one under way finishes and journals
	// its lease before authority ends. Canceling it mid-read is what leaves an
	// unknown issuance behind.
	m.draining.Store(true)
	if err := m.lock(ctx); err == nil {
		m.mu.Unlock()
	}
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
	if releaseErr := m.release(); err == nil {
		err = releaseErr
	}
	m.closeErr = err
	return err
}

// release gives up the owner row once, even after the caller's deadline.
func (m *DurableLeaseMinter) release() error {
	m.releaseOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cancel()
		m.releaseErr = m.journal.ReleaseDatabaseCleanupOwner(ctx, m.owner)
	})
	return m.releaseErr
}

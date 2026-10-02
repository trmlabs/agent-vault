package pgproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// partitionJournal cuts one replica off from the store. While cut, every call
// hangs until its context ends, as a TCP partition would.
type partitionJournal struct {
	CleanupJournal
	cut atomic.Bool
}

func (j *partitionJournal) wait(ctx context.Context) error {
	if !j.cut.Load() {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (j *partitionJournal) RenewDatabaseCleanupOwner(ctx context.Context, owner string, ttl time.Duration) error {
	if err := j.wait(ctx); err != nil {
		return err
	}
	return j.CleanupJournal.RenewDatabaseCleanupOwner(ctx, owner, ttl)
}

func (j *partitionJournal) CheckDatabaseCleanupOwner(ctx context.Context, owner string) error {
	if err := j.wait(ctx); err != nil {
		return err
	}
	return j.CleanupJournal.CheckDatabaseCleanupOwner(ctx, owner)
}

func (j *partitionJournal) ClaimOrphanedDatabaseCleanup(ctx context.Context, owner string) (int, error) {
	if err := j.wait(ctx); err != nil {
		return 0, err
	}
	return j.CleanupJournal.ClaimOrphanedDatabaseCleanup(ctx, owner)
}

func (j *partitionJournal) ListOwnedDatabaseCleanup(ctx context.Context, owner string) ([]store.DatabaseCleanup, error) {
	if err := j.wait(ctx); err != nil {
		return nil, err
	}
	return j.CleanupJournal.ListOwnedDatabaseCleanup(ctx, owner)
}

func (j *partitionJournal) DeleteDatabaseCleanup(ctx context.Context, accessor string) error {
	if err := j.wait(ctx); err != nil {
		return err
	}
	return j.CleanupJournal.DeleteDatabaseCleanup(ctx, accessor)
}

func (j *partitionJournal) ReleaseDatabaseCleanupOwner(ctx context.Context, owner string) error {
	if err := j.wait(ctx); err != nil {
		return err
	}
	return j.CleanupJournal.ReleaseDatabaseCleanupOwner(ctx, owner)
}

var fleetService = &DatabaseService{Name: "db", Mount: "database", Role: "reader"}

func waitWithin(t *testing.T, within time.Duration, what string, ok func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < within {
		if ok() {
			return time.Since(start)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s not within %s", what, within)
	return 0
}

func (f *durableVaultFixture) liveSessions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

// A replica partitioned from the store fences itself, closing its sessions,
// while its owner row is still live by the database clock. Only after the row
// expires does a survivor claim the record and revoke the credential.
func TestDurableLeaseFencesBeforeTakeoverWhenPartitioned(t *testing.T) {
	client, st, vault := durableFixture(t)
	cut := &partitionJournal{CleanupJournal: st}
	a, err := NewDurableLeaseMinter(context.Background(), client, cut, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cut.cut.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Close(ctx)
	})
	if _, err := a.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
		t.Fatal(err)
	}
	survivor, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = survivor.Close(context.Background()) })

	b := New("127.0.0.1:0", Options{Leases: a})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- b.Serve(ln) }()
	session, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	waitWithin(t, 2*time.Second, "session registered", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.conns) == 1 })

	cut.cut.Store(true)
	select {
	case <-a.AuthorityDone():
	case <-time.After(3 * time.Second):
		t.Fatal("partitioned replica did not fence")
	}
	if !a.Fenced() {
		t.Fatal("authority ended without a fence")
	}
	select {
	case err := <-served:
		if !errors.Is(err, ErrAuthorityLost) {
			t.Fatalf("broker stopped with %v, want ErrAuthorityLost so the process restarts", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fenced broker kept serving")
	}
	_ = session.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := session.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("session still open after fence: %v", err)
	}
	// Fenced and closed while the row is still live: nobody could claim yet.
	if err := st.CheckDatabaseCleanupOwner(context.Background(), a.owner); err != nil {
		t.Fatalf("owner row expired before the fence finished: %v", err)
	}
	if records, _ := st.ListOwnedDatabaseCleanup(context.Background(), a.owner); len(records) != 1 {
		t.Fatalf("record left the fenced replica early: %d", len(records))
	}
	if _, err := a.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err == nil {
		t.Fatal("fenced replica minted")
	}
	waitWithin(t, 5*time.Second, "survivor revoked the partitioned replica's credential", func() bool {
		records, err := st.ListDatabaseCleanup(context.Background())
		return err == nil && len(records) == 0 && vault.liveSessions() == 0
	})
}

// A store hiccup shorter than the fence deadline is retried, not fenced.
func TestDurableLeaseSurvivesBriefStoreOutage(t *testing.T) {
	client, st, _ := durableFixture(t)
	cut := &partitionJournal{CleanupJournal: st}
	a, err := NewDurableLeaseMinter(context.Background(), client, cut, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	cut.cut.Store(true)
	time.Sleep(time.Second)
	cut.cut.Store(false)
	time.Sleep(1500 * time.Millisecond)
	if a.Fenced() {
		t.Fatal("brief outage fenced the replica")
	}
	if _, err := a.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
		t.Fatal(err)
	}
}

// Two survivors race to take over a dead replica. Every credential ends up
// revoked and the journal empty, whichever survivor claimed each record.
func TestDurableLeaseTwoSurvivorsTakeOverOnce(t *testing.T) {
	client, st, vault := durableFixture(t)
	dead, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := dead.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
			t.Fatal(err)
		}
	}
	// Crash: stop without releasing the owner row or revoking anything.
	dead.cancel()
	<-dead.done
	var survivors []*DurableLeaseMinter
	for range 2 {
		s, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close(context.Background())
		survivors = append(survivors, s)
	}
	if vault.liveSessions() != 6 {
		t.Fatalf("live sessions before takeover = %d", vault.liveSessions())
	}
	waitWithin(t, 6*time.Second, "takeover", func() bool {
		records, err := st.ListDatabaseCleanup(context.Background())
		return err == nil && len(records) == 0 && vault.liveSessions() == 0
	})
	// The live count is sampled at each heartbeat, so the dead row can still
	// be counted for one beat after the takeover.
	waitWithin(t, 2*time.Second, "survivors count two replicas", func() bool {
		return survivors[0].LiveReplicas() == 2 && survivors[1].LiveReplicas() == 2
	})
	for _, s := range survivors {
		if s.Fenced() {
			t.Fatal("a survivor fenced")
		}
	}
}

// The single-replica deployment: a crashed broker restarts at once as a new
// owner, and its predecessor's credentials are revoked when the old row expires.
func TestDurableLeaseRestartRecoversCrashedPredecessor(t *testing.T) {
	client, st, vault := durableFixture(t)
	old, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
		t.Fatal(err)
	}
	old.cancel()
	<-old.done
	restarted, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal("restart refused while the predecessor's row was live:", err)
	}
	defer restarted.Close(context.Background())
	took := waitWithin(t, 6*time.Second, "predecessor cleanup", func() bool { return vault.liveSessions() == 0 })
	if took < time.Second {
		t.Fatalf("predecessor's credential revoked before its row expired (%s)", took)
	}
	if _, err := restarted.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
		t.Fatal(err)
	}
}

type readinessMinter struct {
	*fakeMinter
	ready atomic.Bool
}

func (m *readinessMinter) Ready() bool { return m.ready.Load() }

// A broker without a fresh owner row refuses new sessions before minting.
func TestBrokerRefusesSessionsUntilReady(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	minter := &readinessMinter{fakeMinter: &fakeMinter{lease: lease}}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable"}},
		Leases:    minter,
	})
	if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "57P03") {
		t.Fatalf("session admitted before ready: %v", err)
	}
	if minter.mintCallCount() != 0 {
		t.Fatal("minted before ready")
	}
	minter.ready.Store(true)
	if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
}

// Readiness follows renewal: a fresh minter is ready at once, a stalled one
// stops taking sessions before it fences, and recovery restores it.
func TestDurableLeaseReadinessFollowsRenewal(t *testing.T) {
	client, st, _ := durableFixture(t)
	cut := &partitionJournal{CleanupJournal: st}
	a, err := NewDurableLeaseMinter(context.Background(), client, cut, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if !a.Ready() {
		t.Fatal("fresh owner row not ready")
	}
	cut.cut.Store(true)
	waitWithin(t, 2*time.Second, "unready while renewals fail", func() bool { return !a.Ready() })
	if a.Fenced() {
		t.Fatal("fenced before going unready")
	}
	cut.cut.Store(false)
	waitWithin(t, 2*time.Second, "ready after recovery", a.Ready)
}

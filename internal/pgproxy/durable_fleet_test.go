package pgproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
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

// Two broker processes configured with the same replica name: the second
// refuses to start while the first keeps renewing, and the first is unharmed.
func TestSecondBrokerWithTheSameReplicaNameRefusesToStart(t *testing.T) {
	client, st, _ := durableFixture(t)
	opts := DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour, Replica: "gatehouse-0"}
	first, err := NewDurableLeaseMinter(context.Background(), client, st, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	start := time.Now()
	second, err := NewDurableLeaseMinter(context.Background(), client, st, opts)
	if err == nil {
		second.Close(context.Background())
		t.Fatal("a second process started under a live replica name")
	}
	if !errors.Is(err, store.ErrReplicaNameInUse) {
		t.Fatalf("refusal = %v, want ErrReplicaNameInUse", err)
	}
	// It waited long enough to tell a live holder from a crashed one.
	if waited := time.Since(start); waited < opts.OwnerTTL {
		t.Fatalf("refused after %s, before a crashed holder's row could expire", waited)
	}
	if first.Fenced() || !first.Ready() {
		t.Fatal("the refused start harmed the live broker")
	}
}

// A restart under the same name after a crash waits for the crashed row to
// expire, then starts: only a holder that is still renewing blocks the name.
func TestRestartUnderTheSameNameWaitsOutTheCrashedRow(t *testing.T) {
	client, st, _ := durableFixture(t)
	opts := DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour, Replica: "gatehouse-0"}
	old, err := NewDurableLeaseMinter(context.Background(), client, st, opts)
	if err != nil {
		t.Fatal(err)
	}
	old.cancel() // crash: no release
	<-old.done
	start := time.Now()
	restarted, err := NewDurableLeaseMinter(context.Background(), client, st, opts)
	if err != nil {
		t.Fatal("restart after a crash refused:", err)
	}
	defer restarted.Close(context.Background())
	if waited := time.Since(start); waited < time.Second {
		t.Fatalf("started after %s, while the crashed row was still live", waited)
	}
}

// The same guard across real processes sharing one store file: the child
// broker process, configured with the parent's replica name, exits refusing.
func TestSecondBrokerProcessWithTheSameNameRefuses(t *testing.T) {
	if os.Getenv("GH_REPLICA_GUARD_DB") != "" {
		t.Skip("helper process")
	}
	path := filepath.Join(t.TempDir(), "journal.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	client, _, _ := durableFixtureOn(t, st)
	first, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour, Replica: "gatehouse-0"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplicaGuardHelperProcess$", "-test.count=1") // #nosec G702 -- re-runs this test binary
	cmd.Env = append(os.Environ(), "GH_REPLICA_GUARD_DB="+path)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("second process did not refuse (err %v):\n%s", err, out)
	}
	if first.Fenced() {
		t.Fatal("the refused process fenced the live broker")
	}
}

func TestReplicaGuardHelperProcess(t *testing.T) {
	path := os.Getenv("GH_REPLICA_GUARD_DB")
	if path == "" {
		t.Skip("run by TestSecondBrokerProcessWithTheSameNameRefuses")
	}
	st, err := store.Open(path)
	if err != nil {
		os.Exit(2)
	}
	client, _, _ := durableFixtureOn(t, st)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour, Replica: "gatehouse-0"})
	if errors.Is(err, store.ErrReplicaNameInUse) {
		os.Exit(3)
	}
	if err == nil {
		m.Close(context.Background())
	}
	os.Exit(4)
}

// A planned restart: the broker process gets SIGTERM, revokes its leases and
// releases its owner row, so a new process under the same replica name
// registers at once instead of waiting out the row.
func TestGracefulRestartReRegistersAtOnce(t *testing.T) {
	if os.Getenv("GH_REPLICA_RESTART_DB") != "" {
		t.Skip("helper process")
	}
	path := filepath.Join(t.TempDir(), "journal.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplicaRestartHelperProcess$", "-test.count=1") // #nosec G702 -- re-runs this test binary
	cmd.Env = append(os.Environ(), "GH_REPLICA_RESTART_DB="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "registered" {
				close(ready)
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper broker never registered")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper broker did not stop cleanly: %v", err)
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if records, err := st.ListDatabaseCleanup(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("leases left after a graceful stop: %d %v", len(records), err)
	}
	client, _, _ := durableFixtureOn(t, st)
	start := time.Now()
	restarted, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 30 * time.Second, Replica: "gatehouse-0"})
	if err != nil {
		t.Fatal("restart refused:", err)
	}
	defer restarted.Close(context.Background())
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("restart registered after %s, want under 5 s", took)
	}
}

// TestReplicaRestartHelperProcess is the broker being restarted: it registers,
// mints one lease, and on SIGTERM closes as the server does on shutdown.
func TestReplicaRestartHelperProcess(t *testing.T) {
	path := os.Getenv("GH_REPLICA_RESTART_DB")
	if path == "" {
		t.Skip("run by TestGracefulRestartReRegistersAtOnce")
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	st, err := store.Open(path)
	if err != nil {
		os.Exit(2)
	}
	client, _, _ := durableFixtureOn(t, st)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 30 * time.Second, Replica: "gatehouse-0"})
	if err != nil {
		os.Exit(3)
	}
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, fleetService); err != nil {
		os.Exit(4)
	}
	fmt.Println("registered")
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if m.Close(ctx) != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

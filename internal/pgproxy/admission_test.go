package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type slowRevokeMinter struct {
	*fakeMinter
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (m *slowRevokeMinter) Revoke(ctx context.Context, id string) error {
	m.once.Do(func() { close(m.entered) })
	select {
	case <-m.release:
		return m.fakeMinter.Revoke(ctx, id)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAdmissionWaitsForCleanupWithoutMintingOrUnboundedPending(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	m := &slowRevokeMinter{fakeMinter: &fakeMinter{lease: newLease()}, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(m.release) })
	defer release()
	b, addr := startBroker(t, Options{MaxConns: 1, MaxPendingConns: 1, AdmissionTimeout: time.Second,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			return &AgentScope{VaultID: "v", ActorID: token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: m})
	first := openAgentSession(t, addr, "first", "db")
	first.close()
	select {
	case <-m.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	done := make(chan struct{})
	var second *agentSession
	go func() { defer close(done); second = openAgentSession(t, addr, "second", "db") }()
	waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 1 }, "queued connection did not retain pending slot")
	if m.mintCallCount() != 1 {
		t.Fatal("queued connection minted before cleanup released capacity")
	}
	overflow := overflowWaits(t, b, addr)
	select {
	case <-done:
		t.Fatal("admission failed instead of waiting for cleanup")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capacity release did not wake queued connection")
	}
	if second == nil {
		t.Fatal("queued connection did not establish")
	}
	defer second.close()
	// The overflow is accepted once the queued connection is served, and is
	// refused at serving capacity without a mint.
	if code := <-overflow; code != "53300" {
		t.Fatalf("overflow ended with %q", code)
	}
	if m.mintCallCount() != 2 || len(b.acceptSem) != 0 {
		t.Fatal("admission did not release pending slot or mint exactly once")
	}
}

func TestAdmissionTimeoutAndShutdownCancelWithoutMinting(t *testing.T) {
	for _, mode := range []string{"timeout", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			up := startFakeUpstream(t, authTrust, "")
			m := &fakeMinter{lease: newLease()}
			b, addr := startBroker(t, Options{MaxConns: 1, AdmissionTimeout: 50 * time.Millisecond,
				Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
					return &AgentScope{VaultID: "v", ActorID: token}, nil
				}),
				Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: m})
			first := openAgentSession(t, addr, "first", "db")
			defer first.close()
			done := make(chan string, 1)
			go func() { done <- connectExpectCode(t, addr, "second", "db") }()
			if mode == "shutdown" {
				waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 1 }, "connection did not queue")
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := b.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case code := <-done:
				if mode == "timeout" && code != "53300" {
					t.Fatalf("want capacity error, got %q", code)
				}
			case <-time.After(time.Second):
				t.Fatal("admission wait leaked")
			}
			if m.mintCallCount() != 1 {
				t.Fatal("rejected admission minted a credential")
			}
			waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 0 }, "pending slot leaked")
		})
	}
}

func TestActorAdmissionWaitsForCleanupWithoutMintingOrUnboundedPending(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	m := &slowRevokeMinter{fakeMinter: &fakeMinter{lease: newLease()}, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(m.release) })
	defer release()
	b, addr := startBroker(t, Options{MaxConns: 2, MaxLeasesPerActor: 1, MaxPendingConns: 1, AdmissionTimeout: time.Second,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			return &AgentScope{VaultID: "v", ActorID: token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: m})
	first := openAgentSession(t, addr, "first", "db")
	first.close()
	select {
	case <-m.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	done := make(chan struct{})
	var second *agentSession
	go func() { defer close(done); second = openAgentSession(t, addr, "first", "db") }()
	waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 1 }, "queued connection did not retain pending slot")
	if m.mintCallCount() != 1 {
		t.Fatal("queued connection minted before cleanup released capacity")
	}
	overflow := overflowWaits(t, b, addr)
	select {
	case <-done:
		t.Fatal("admission failed instead of waiting for cleanup")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capacity release did not wake queued connection")
	}
	if second == nil {
		t.Fatal("queued connection did not establish")
	}
	defer second.close()
	// The overflow, another actor, is accepted and served once the queued
	// connection is.
	if code := <-overflow; code != "OK" {
		t.Fatalf("overflow ended with %q", code)
	}
	if m.mintCallCount() != 3 || len(b.acceptSem) != 0 {
		t.Fatal("admission did not release pending slot or mint once per session")
	}
}

func TestActorAdmissionDeadlineAndShutdown(t *testing.T) {
	for _, mode := range []string{"timeout", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			up := startFakeUpstream(t, authTrust, "")
			m := &fakeMinter{lease: newLease()}
			b, addr := startBroker(t, Options{MaxConns: 2, MaxLeasesPerActor: 1, AdmissionTimeout: 30 * time.Millisecond,
				Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
					return &AgentScope{VaultID: "v", ActorID: token}, nil
				}),
				Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: m})
			first := openAgentSession(t, addr, "same", "db")
			defer first.close()
			done := make(chan string, 1)
			go func() { done <- connectExpectCode(t, addr, "same", "db") }()
			if mode == "shutdown" {
				waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 1 }, "actor admission not pending")
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := b.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case code := <-done:
				if mode == "timeout" && code != "53300" {
					t.Fatalf("expected capacity error: %q", code)
				}
			case <-time.After(time.Second):
				t.Fatal("actor wait leaked")
			}
			if m.mintCallCount() != 1 {
				t.Fatal("waiting actor minted credential")
			}
			waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 0 }, "pending slot leaked")
		})
	}
}

func TestActorAdmissionRechecksRevocationAndScopeBeforeMint(t *testing.T) {
	for _, mode := range []string{"revoked", "actor", "vault", "workload", "verifier-outage", "late-valid"} {
		t.Run(mode, func(t *testing.T) {
			up := startFakeUpstream(t, authTrust, "")
			m := &slowRevokeMinter{fakeMinter: &fakeMinter{lease: newLease()}, entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(m.release) })
			defer release()
			var changed atomic.Bool
			var authCalls atomic.Int32
			b, addr := startBroker(t, Options{MaxConns: 2, MaxLeasesPerActor: 1, AdmissionTimeout: time.Second, AuthorizationTimeout: 20 * time.Millisecond,
				Auth: authFunc(func(ctx context.Context, token, _ string) (*AgentScope, error) {
					scope := &AgentScope{VaultID: "v", ActorID: token, WorkloadID: "w"}
					if changed.Load() {
						switch mode {
						case "revoked":
							return nil, errors.New("revoked")
						case "verifier-outage":
							return nil, errors.New("unavailable")
						case "late-valid":
							<-ctx.Done()
						case "actor":
							scope.ActorID = "other"
						case "vault":
							scope.VaultID = "other"
						case "workload":
							scope.WorkloadID = "other"
						}
					}
					authCalls.Add(1)
					return scope, nil
				}), Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: m})
			first := openAgentSession(t, addr, "same", "db")
			first.close()
			select {
			case <-m.entered:
			case <-time.After(time.Second):
				t.Fatal("cleanup did not start")
			}
			done := make(chan string, 1)
			go func() { done <- connectExpectCode(t, addr, "same", "db") }()
			waitFor(t, time.Second, func() bool { return len(b.acceptSem) == 1 && authCalls.Load() >= 3 }, "actor request not pending")
			changed.Store(true)
			release()
			select {
			case code := <-done:
				if code != "28000" {
					t.Fatalf("expected auth denial, got %q", code)
				}
			case <-time.After(time.Second):
				t.Fatal("request did not finish")
			}
			if m.mintCallCount() != 1 {
				t.Fatal("withdrawn or changed actor minted")
			}
			waitFor(t, time.Second, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.leaseCounts) == 0 }, "actor slot leaked")
		})
	}
}

// overflowWaits starts a connection past the pending bound and checks that it
// waits to be accepted: no answer and no pending slot while the bound holds.
func overflowWaits(t *testing.T, b *Broker, addr string) <-chan string {
	t.Helper()
	overflow := make(chan string, 1)
	go func() { overflow <- connectExpectCode(t, addr, "overflow", "db") }()
	time.Sleep(200 * time.Millisecond)
	select {
	case code := <-overflow:
		t.Fatalf("overflow answered while the pending slot was held: %q", code)
	default:
	}
	if len(b.acceptSem) != 1 {
		t.Fatal("overflow took a pending slot")
	}
	return overflow
}

// A burst far past the pending bound and the admission concurrency is
// queued, not refused: with a store that answers one call at a time, every
// connection of the burst is served.
func TestBurstQueuesInsteadOfRefusing(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	var store sync.Mutex // one connection, like the SQLite store
	_, addr := startBroker(t, Options{MaxPendingConns: 4, AdmissionConcurrency: 2,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			store.Lock()
			defer store.Unlock()
			time.Sleep(2 * time.Millisecond)
			return &AgentScope{VaultID: "v", ActorID: token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
	const burst = 100
	codes := make(chan string, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- connectExpectCode(t, addr, fmt.Sprintf("agent-%d", i), "db")
		}()
	}
	wg.Wait()
	close(codes)
	counts := map[string]int{}
	for code := range codes {
		counts[code]++
	}
	if counts["OK"] != burst {
		t.Fatalf("burst of %d: %v", burst, counts)
	}
}

// slowLedger answers each Add after delay, unless its deadline comes first.
type slowLedger struct{ delay time.Duration }

func (l slowLedger) Add(ctx context.Context, _, _ string, _ int) error {
	select {
	case <-time.After(l.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (slowLedger) Remove(context.Context, string) error { return nil }

// A slow session ledger has its own deadline and does not spend the wait for
// serving capacity: an Add that outlasts AdmissionTimeout but not
// LedgerTimeout still admits, and one past LedgerTimeout is refused as the
// ledger, not as the serving cap.
func TestSlowLedgerHasItsOwnDeadline(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	start := func(ledger time.Duration) string {
		_, addr := startBroker(t, Options{AdmissionTimeout: 100 * time.Millisecond, LedgerTimeout: 400 * time.Millisecond,
			Sessions: slowLedger{delay: ledger},
			Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
				return &AgentScope{VaultID: "v", ActorID: token, WorkloadID: "pod-1"}, nil
			}),
			Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
		return connectExpectCode(t, addr, "agent", "db")
	}
	if code := start(200 * time.Millisecond); code != "OK" {
		t.Fatalf("ledger slower than the admission timeout: %q", code)
	}
	if code := start(time.Second); code != "08004" {
		t.Fatalf("ledger past its own deadline: %q", code)
	}
}

// Admission's store calls never run more than AdmissionConcurrency at once,
// whatever the pending bound lets in.
func TestAdmissionConcurrencyBoundsStoreCalls(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	var inFlight, peak atomic.Int32
	_, addr := startBroker(t, Options{MaxPendingConns: 1000, AdmissionConcurrency: 2,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(5 * time.Millisecond)
			return &AgentScope{VaultID: "v", ActorID: token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
	var wg sync.WaitGroup
	var served atomic.Int32
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if connectExpectCode(t, addr, fmt.Sprintf("agent-%d", i), "db") == "OK" {
				served.Add(1)
			}
		}()
	}
	wg.Wait()
	if served.Load() != 60 || peak.Load() > 2 {
		t.Fatalf("served %d of 60, peak store calls %d", served.Load(), peak.Load())
	}
}

// A connection that waited in the admission queue past its startup deadline
// still receives its refusal, not a dropped connection.
func TestQueuedRefusalReachesTheClient(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	held, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	_, addr := startBroker(t, Options{AdmissionConcurrency: 1, StartupTimeout: 100 * time.Millisecond, HandshakeTimeout: 400 * time.Millisecond,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			if token == "holder" {
				close(held)
				<-release
			}
			return &AgentScope{VaultID: "v", ActorID: token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
	go connectExpectCode(t, addr, "holder", "db")
	<-held
	if code := connectExpectCode(t, addr, "queued", "db"); code != "53300" {
		t.Fatalf("queued refusal: %q", code)
	}
}

// One workload at its own cap opens more connections. While they wait for its
// per-workload slot they hold no admission slot, so another workload's
// admission does not stall behind them.
func TestWorkloadAtItsCapDoesNotStallOthers(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	_, addr := startBroker(t, Options{AdmissionConcurrency: 2, MaxLeasesPerActor: 1, AdmissionTimeout: 1500 * time.Millisecond,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			return &AgentScope{VaultID: "v", ActorID: token, WorkloadID: "pod-" + token}, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
	held := openAgentSession(t, addr, "hog", "db")
	defer held.close()
	codes := make(chan string, 2)
	for range 2 {
		go func() { codes <- connectExpectCode(t, addr, "hog", "db") }()
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	code := connectExpectCode(t, addr, "victim", "db")
	if elapsed := time.Since(start); code != "OK" || elapsed > 500*time.Millisecond {
		t.Fatalf("victim %q after %s behind a workload waiting at its own cap", code, elapsed)
	}
	<-codes
	<-codes
}

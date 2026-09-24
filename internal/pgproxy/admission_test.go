package pgproxy

import (
	"context"
	"errors"
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
	if code := connectExpectCode(t, addr, "overflow", "db"); code != "" {
		t.Fatalf("overflow should be closed before authentication: %s", code)
	}
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
	if code := connectExpectCode(t, addr, "overflow", "db"); code != "" {
		t.Fatalf("overflow should be closed before authentication: %s", code)
	}
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
	if m.mintCallCount() != 2 || len(b.acceptSem) != 0 {
		t.Fatal("admission did not release pending slot or mint exactly once")
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

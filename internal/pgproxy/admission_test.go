package pgproxy

import (
	"context"
	"sync"
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

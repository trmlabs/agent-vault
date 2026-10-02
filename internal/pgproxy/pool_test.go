package pgproxy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// With pooling on, client sessions share server connections and one
// credential; with it off (every other test in this package) each session
// mints its own, unchanged.
func TestPooledSessionsShareServerConnectionsAndOneCredential(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	minter := &fakeMinter{lease: lease}
	audit := &recordingAudit{}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 2}},
		Leases:    minter,
		Pool:      &PoolOptions{QueueFactor: 20},
		Audit:     audit,
	})
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT current_user")
			if err == nil && got != lease.Username {
				t.Errorf("query answered %q", got)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	upstream.mu.Lock()
	accepted := upstream.accepted
	upstream.mu.Unlock()
	if accepted < 1 || accepted > 2 {
		t.Fatalf("12 sessions opened %d upstream connections, budget 2", accepted)
	}
	if minter.mintCallCount() != 1 {
		t.Fatalf("minted %d credentials, want one shared", minter.mintCallCount())
	}
	waitFor(t, 2*time.Second, func() bool {
		n := 0
		for _, e := range audit.recorded() {
			if e.Event == "transaction" && e.Pool == "cursor" {
				n++
			}
		}
		return n == 12
	}, "one audited transaction per session")
}

// Budgets follow the fleet: when another replica joins, idle connections above
// the smaller share close, so the replicas together stay within the budget.
func TestPooledBudgetFollowsLiveReplicas(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	var live atomic.Int64
	live.Store(1)
	svc := &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}
	b, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: svc},
		Leases:    &fakeMinter{lease: lease},
		Pool:      &PoolOptions{QueueFactor: 20, LiveReplicas: func() int { return int(live.Load()) }},
	})
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT pg_sleep(0)"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if open, _ := b.pools.stats(svc.Addr); open > 4 {
		t.Fatalf("one replica opened %d, budget 4", open)
	}
	live.Store(2)
	waitFor(t, 3*time.Second, func() bool { open, _ := b.pools.stats(svc.Addr); return open <= 2 }, "share shrank to 2")
	live.Store(4)
	waitFor(t, 3*time.Second, func() bool { open, _ := b.pools.stats(svc.Addr); return open <= 1 }, "share shrank to 1")
	if _, err := runAgentQuery(t, addr, "agent-vault-token", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if open, _ := b.pools.stats(svc.Addr); open > 1 {
		t.Fatalf("opened %d beyond the share of 1", open)
	}
}

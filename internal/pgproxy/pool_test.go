package pgproxy

import (
	"errors"
	"sync"
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

// A pooled session ends at its Pod's deadline, as an unpooled one does.
func TestPooledSessionEndsAtTheDeadline(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	_, addr := startBroker(t, Options{
		Auth: &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor",
			NotAfter: time.Now().Add(700 * time.Millisecond)}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable"}},
		Leases:    &fakeMinter{lease: lease},
		Pool:      &PoolOptions{},
	})
	conn, err := openSession(t, addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	started := time.Now()
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			var timeout interface{ Timeout() bool }
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("pooled session outlived its deadline")
			}
			break
		}
	}
	if time.Since(started) > 2500*time.Millisecond {
		t.Fatal("session ended late")
	}
}

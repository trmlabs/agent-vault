package pgproxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// vaultLikeMinter models HashiCorp Vault's lease renewal semantics: a lease
// expires at a moving `expiry` capped by `maxExpiry`; a renew grants
// min(now+increment, maxExpiry); renewing a lease that has already expired
// fails ("lease not found"), because Vault garbage-collects expired leases.
// This is what makes the renewal-increment decay bug observable in a fast unit
// test without waiting real Vault TTLs.
type vaultLikeMinter struct {
	initTTL time.Duration
	maxTTL  time.Duration

	mu         sync.Mutex
	mintCalls  int
	increments []time.Duration // the increment requested on each Renew call
	revoked    []string
	expiry     map[string]time.Time
	maxExpiry  map[string]time.Time
}

func newVaultLikeMinter(initTTL, maxTTL time.Duration) *vaultLikeMinter {
	return &vaultLikeMinter{initTTL: initTTL, maxTTL: maxTTL, expiry: map[string]time.Time{}, maxExpiry: map[string]time.Time{}}
}

func (m *vaultLikeMinter) Mint(_ context.Context, _ string, _ *DatabaseService) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mintCalls++
	id := fmt.Sprintf("lease-%d", m.mintCalls)
	now := time.Now()
	m.expiry[id] = now.Add(m.initTTL)
	m.maxExpiry[id] = now.Add(m.maxTTL)
	return &Lease{ID: id, Username: "v-user", Password: "pw", ExpiresAt: m.expiry[id], Renewable: true}, nil
}

func (m *vaultLikeMinter) Renew(_ context.Context, leaseID string, increment time.Duration) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.increments = append(m.increments, increment)
	now := time.Now()
	exp, ok := m.expiry[leaseID]
	if !ok || now.After(exp) {
		return time.Time{}, fmt.Errorf("lease not found") // Vault GC'd the expired lease
	}
	granted := now.Add(increment)
	if granted.After(m.maxExpiry[leaseID]) {
		granted = m.maxExpiry[leaseID]
	}
	m.expiry[leaseID] = granted
	return granted, nil
}

func (m *vaultLikeMinter) Revoke(_ context.Context, leaseID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked = append(m.revoked, leaseID)
	delete(m.expiry, leaseID)
	return nil
}

func (m *vaultLikeMinter) requestedIncrements() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]time.Duration(nil), m.increments...)
}

// TestBroker_RenewalRequestsConstantGenerousIncrement guards the renewal
// increment contract: each renew must request a stable, generous increment (the
// credential's initial TTL), not the shrinking remaining time. Requesting
// `remaining + floor` makes each grant hug the current expiry, so the session
// survives only by a millisecond-thin, ever-tightening margin — one slow Vault
// round-trip or scheduler pause near expiry then kills a healthy long-lived
// session, and the loop makes many small renew calls instead of few large ones.
// The constant-increment path jumps straight to max TTL each cycle: a wide
// margin and a bounded number of Vault calls. This asserts the requested
// increment directly, so it fails on the shrinking-increment behavior
// regardless of whether that behavior happens to reach a stable fixed point at
// any particular set of timings.
func TestBroker_RenewalRequestsConstantGenerousIncrement(t *testing.T) {
	const initTTL = 1 * time.Second
	minter := newVaultLikeMinter(initTTL, 5*time.Second)
	upstream := startFakeUpstream(t, authTrust, "")
	_, addr := startBroker(t, Options{
		Auth:             &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases:        &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:           minter,
		MinRenewInterval: 100 * time.Millisecond,
	})

	session := openAgentSession(t, addr, "tok", "appdb")
	defer session.close()

	// Well past the 1s initial TTL the session must still be usable via renewal.
	time.Sleep(2500 * time.Millisecond)
	if _, err := session.query("SELECT 1"); err != nil {
		t.Fatalf("session died before max TTL: %v", err)
	}

	// Every requested increment must be generous (~the initial TTL). The
	// shrinking `remaining + floor` path requests increments far below this —
	// hugging expiry — so it fails here even where it happens to survive.
	increments := minter.requestedIncrements()
	if len(increments) < 2 {
		t.Fatalf("expected multiple renewals, got %d", len(increments))
	}
	minIncrement := initTTL - initTTL/10 // 90% of the initial TTL
	for i, inc := range increments {
		if inc < minIncrement {
			t.Fatalf("renew %d requested a shrinking increment %v (< %v); renewal-increment decay regression", i, inc, minIncrement)
		}
	}

	// Near/after max TTL (5s) the session must be terminated (enforceExpiry).
	waitFor(t, 6*time.Second, func() bool {
		_, err := session.query("SELECT 1")
		return err != nil
	}, "session was not terminated at max TTL")
}

// TestBroker_HalfOpenDoesNotStarveServing proves that connections stalled before
// authentication do not consume the serving cap, so real agents are still served
// during a half-open flood.
func TestBroker_HalfOpenDoesNotStarveServing(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: lease}
	_, addr := startBroker(t, Options{
		Auth:            &fakeAuth{scope: &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: "a1"}},
		Databases:       &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:          minter,
		MaxConns:        4,
		MaxPendingConns: 64,
		StartupTimeout:  500 * time.Millisecond,
	})

	// Open many raw sockets that never send a startup packet.
	var stalled []net.Conn
	for i := 0; i < 20; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			stalled = append(stalled, c)
		}
	}
	defer func() {
		for _, c := range stalled {
			_ = c.Close()
		}
	}()

	// A real agent must still authenticate and be served.
	got, err := runAgentQuery(t, addr, "tok", "appdb", "SELECT current_user")
	if err != nil {
		t.Fatalf("real agent starved by half-open flood: %v", err)
	}
	if got != lease.Username {
		t.Fatalf("got %q, want minted %q", got, lease.Username)
	}
}

// multiResolver routes by requested database name to distinct services.
type multiResolver struct{ byName map[string]*DatabaseService }

func (r multiResolver) ResolveDatabase(_ context.Context, _ AgentScope, requested string) (*DatabaseService, error) {
	if svc, ok := r.byName[requested]; ok {
		return svc, nil
	}
	return nil, fmt.Errorf("no database service %q", requested)
}

// TestBroker_PerDatabaseBudgetIsolation proves a burst that saturates one
// database's per-upstream budget does not starve connections to another.
func TestBroker_PerDatabaseBudgetIsolation(t *testing.T) {
	upA := startFakeUpstream(t, authTrust, "")
	upB := startFakeUpstream(t, authTrust, "")
	svcA := &DatabaseService{Name: "dbA", Addr: upA.addr(), Mount: "database", Role: "ro", SSLMode: "disable", MaxConns: 2}
	svcB := &DatabaseService{Name: "dbB", Addr: upB.addr(), Mount: "database", Role: "ro", SSLMode: "disable", MaxConns: 2}
	_, addr := startBroker(t, Options{
		Auth:              tokenActorAuth{},
		Databases:         multiResolver{byName: map[string]*DatabaseService{"dbA": svcA, "dbB": svcB}},
		Leases:            &fakeMinter{lease: newLease()},
		MaxConns:          10, // global backstop, well above the per-database caps
		MaxLeasesPerActor: 100,
	})

	// Fill dbA's per-database budget (2).
	a1 := openAgentSession(t, addr, "agent1", "dbA")
	a2 := openAgentSession(t, addr, "agent2", "dbA")
	defer a1.close()
	defer a2.close()
	// A third dbA connection is refused — dbA's budget is full...
	if code := connectExpectCode(t, addr, "agent3", "dbA"); code != "53300" {
		t.Fatalf("dbA over its per-database budget: expected 53300, got %q", code)
	}
	// ...but dbB is unaffected: one database's saturation does not starve another.
	b1 := openAgentSession(t, addr, "agent4", "dbB")
	defer b1.close()
	if _, err := b1.query("SELECT 1"); err != nil {
		t.Fatalf("dbB starved by dbA saturation: %v", err)
	}
}

// tokenActorAuth derives the actor id from the token so distinct tokens model
// distinct agents.
type tokenActorAuth struct{}

func (tokenActorAuth) Authenticate(_ context.Context, token, _ string) (*AgentScope, error) {
	return &AgentScope{VaultID: "v1", VaultName: "demo", ActorID: token}, nil
}

// TestBroker_PerActorCapDoesNotStarveOtherActors proves the per-actor cap keeps
// one noisy agent from monopolizing the serving cap: actor A is bounded at its
// per-actor limit while a different actor B still gets served.
func TestBroker_PerActorCapDoesNotStarveOtherActors(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth:              tokenActorAuth{},
		Databases:         &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:            minter,
		MaxConns:          10,
		MaxLeasesPerActor: 3,
	})

	// Actor A fills its per-actor cap (3), leaving the global serving cap far
	// from full.
	var aSessions []*agentSession
	for i := 0; i < 3; i++ {
		aSessions = append(aSessions, openAgentSession(t, addr, "actorA", "appdb"))
	}
	defer func() {
		for _, s := range aSessions {
			s.close()
		}
	}()
	// A's 4th connection is refused (per-actor cap), even though slots are free.
	if code := connectExpectCode(t, addr, "actorA", "appdb"); code != "53300" {
		t.Fatalf("actor A over its per-actor cap: expected 53300, got %q", code)
	}
	// A different actor B is still served — A cannot starve others.
	b := openAgentSession(t, addr, "actorB", "appdb")
	defer b.close()
	if _, err := b.query("SELECT 1"); err != nil {
		t.Fatalf("actor B starved by actor A: %v", err)
	}
}

// TestBroker_ServingCapRejectsOverLimit proves the serving cap bounds upstream
// connections: when MaxConns sessions are live, the next is rejected (not
// dangling), protecting the database from saturation.
func TestBroker_ServingCapRejectsOverLimit(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			return &AgentScope{VaultID: "v1", ActorID: token}, nil
		}),
		Databases:         &fakeResolver{svc: &DatabaseService{Name: "svc", Addr: upstream.addr(), Mount: "database", Role: "ro", SSLMode: "disable"}},
		Leases:            minter,
		MaxConns:          2,
		AdmissionTimeout:  20 * time.Millisecond,
		MaxLeasesPerActor: 2, // distinct actors exercise the global cap
	})

	first := openAgentSession(t, addr, "first", "appdb")
	defer first.close()
	second := openAgentSession(t, addr, "second", "appdb")
	defer second.close()

	// Two serving slots are held; the third connection is rejected.
	if code := connectExpectCode(t, addr, "third", "appdb"); code != "53300" {
		t.Fatalf("expected 53300 (serving cap), got %q", code)
	}
}

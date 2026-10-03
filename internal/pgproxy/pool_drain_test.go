package pgproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// drainBroker is a pooled broker over a fake upstream with transactions.
func drainBroker(t *testing.T, drain bool) (*Broker, string) {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	upstream.mu.Lock()
	upstream.transactions = true
	upstream.mu.Unlock()
	return startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}},
		Leases:    &fakeMinter{lease: lease},
		Pool:      &PoolOptions{QueueFactor: 20, DrainSessions: drain},
	})
}

type drainClient struct {
	t    *testing.T
	conn net.Conn
	fe   *pgproto3.Frontend
}

func openDrainClient(t *testing.T, addr string) *drainClient {
	t.Helper()
	conn, err := openSession(t, addr, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &drainClient{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn)}
}

// query runs one simple query and returns its ReadyForQuery status.
func (c *drainClient) query(sql string) byte {
	c.t.Helper()
	c.fe.Send(&pgproto3.Query{String: sql})
	if err := c.fe.Flush(); err != nil {
		c.t.Fatalf("%s: %v", sql, err)
	}
	for {
		msg, err := c.fe.Receive()
		if err != nil {
			c.t.Fatalf("%s: %v", sql, err)
		}
		switch m := msg.(type) {
		case *pgproto3.ReadyForQuery:
			return m.TxStatus
		case *pgproto3.ErrorResponse:
			c.t.Fatalf("%s: %s %s", sql, m.Code, m.Message)
		}
	}
}

// ending reads what the session ends with: the restart notice's code, or ""
// when the connection closes without one.
func (c *drainClient) ending() string {
	c.t.Helper()
	msg, err := c.fe.Receive()
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			c.t.Fatal("session still open")
		}
		return ""
	}
	m, ok := msg.(*pgproto3.ErrorResponse)
	if !ok || m.Severity != "FATAL" {
		c.t.Fatalf("session ended with %T %+v", msg, msg)
	}
	if _, err := c.fe.Receive(); err == nil {
		c.t.Fatal("session open after its FATAL")
	}
	return m.Code
}

func shutdownBroker(b *Broker, timeout time.Duration) <-chan error {
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		done <- b.Shutdown(ctx)
	}()
	return done
}

func TestPooledDrainEndsAnIdleSessionWithRestart(t *testing.T) {
	b, addr := drainBroker(t, true)
	c := openDrainClient(t, addr)
	c.query("SELECT 1")
	done := shutdownBroker(b, 10*time.Second)
	if code := c.ending(); code != "57P01" {
		t.Fatalf("idle session ended with %q, want 57P01", code)
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestPooledDrainLetsAnOpenTransactionFinish(t *testing.T) {
	b, addr := drainBroker(t, true)
	c := openDrainClient(t, addr)
	if status := c.query("BEGIN"); status != 'T' {
		t.Fatalf("BEGIN left status %q", status)
	}
	done := shutdownBroker(b, 10*time.Second)
	time.Sleep(200 * time.Millisecond)
	if status := c.query("SLEEP"); status != 'T' {
		t.Fatalf("a statement inside the transaction during the drain left status %q", status)
	}
	if status := c.query("COMMIT"); status != 'I' {
		t.Fatalf("COMMIT left status %q", status)
	}
	if code := c.ending(); code != "57P01" {
		t.Fatalf("session after COMMIT ended with %q, want 57P01", code)
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestPooledDrainEndsAPinnedIdleSession(t *testing.T) {
	b, addr := drainBroker(t, true)
	c := openDrainClient(t, addr)
	c.query("SET search_path = analytics")
	done := shutdownBroker(b, 10*time.Second)
	if code := c.ending(); code != "57P01" {
		t.Fatalf("pinned idle session ended with %q, want 57P01", code)
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestPooledDrainCutsATransactionStillOpenAtTheDeadline(t *testing.T) {
	b, addr := drainBroker(t, true)
	c := openDrainClient(t, addr)
	c.query("BEGIN")
	started := time.Now()
	done := shutdownBroker(b, drainReserve+300*time.Millisecond)
	if code := c.ending(); code != "" {
		t.Fatalf("a cut transaction got %q; it must not look like a clean restart", code)
	}
	if elapsed := time.Since(started); elapsed < 250*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("transaction cut after %v, want at the drain deadline", elapsed)
	}
	<-done
}

// Without DrainSessions, Shutdown keeps its old behavior: every session,
// even one inside a transaction, closes at once without a notice.
func TestPooledShutdownWithoutDrainClosesAtOnce(t *testing.T) {
	b, addr := drainBroker(t, false)
	c := openDrainClient(t, addr)
	c.query("BEGIN")
	started := time.Now()
	done := shutdownBroker(b, 10*time.Second)
	if code := c.ending(); code != "" {
		t.Fatalf("undrained session ended with %q, want a plain close", code)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("undrained session closed after %v", elapsed)
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// authorityMinter is a lease minter whose cleanup authority the test ends.
type authorityMinter struct {
	fakeMinter
	done chan struct{}
}

func (m *authorityMinter) AuthorityDone() <-chan struct{} { return m.done }

// Losing cleanup authority during a drain ends the busy sessions at once: the
// drain would otherwise keep them on credentials other replicas may already
// have claimed and revoked.
func TestPooledDrainStopsWhenCleanupAuthorityIsLost(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	upstream.mu.Lock()
	upstream.transactions = true
	upstream.mu.Unlock()
	minter := &authorityMinter{fakeMinter: fakeMinter{lease: lease}, done: make(chan struct{})}
	b, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}},
		Leases:    minter,
		Pool:      &PoolOptions{QueueFactor: 20, DrainSessions: true},
	})
	c := openDrainClient(t, addr)
	c.query("BEGIN")
	done := shutdownBroker(b, 30*time.Second)
	time.Sleep(200 * time.Millisecond)
	started := time.Now()
	close(minter.done)
	if code := c.ending(); code != "" {
		t.Fatalf("session ended with %q; a lost-authority stop is not a clean restart", code)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("busy session outlived lost authority by %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not finish after authority was lost")
	}
}

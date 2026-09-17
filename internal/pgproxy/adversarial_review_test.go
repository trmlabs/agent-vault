package pgproxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestAdversarial_UnauthenticatedPasswordLengthAllocation(t *testing.T) {
	_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent"}})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.Receive(); err != nil {
		t.Fatal(err)
	}
	// An oversized header must be rejected without waiting for its body.
	header := []byte{'p', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:], 32*1024*1024+4)
	if _, err := conn.Write(header); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	msg, err := fe.Receive()
	if err == nil {
		if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
			t.Fatalf("expected rejection, got %T", msg)
		}
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("broker waited for oversized password body")
	}

}

type stalledReviewMinter struct {
	*fakeMinter
	entered chan struct{}
}

func (m *stalledReviewMinter) Renew(ctx context.Context, _ string, _ time.Duration) (time.Time, error) {
	close(m.entered)
	<-ctx.Done()
	return time.Time{}, ctx.Err()
}

func TestAdversarial_ExpiredSessionDuringStalledRenew(t *testing.T) {
	lease := &Lease{ID: "review", Username: "review-user", Password: "synthetic", ExpiresAt: time.Now().Add(300 * time.Millisecond), Renewable: true}
	upstream := startFakeUpstream(t, authTrust, "")
	m := &stalledReviewMinter{fakeMinter: &fakeMinter{lease: lease}, entered: make(chan struct{})}
	_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: upstream.addr()}}, Leases: m, MinRenewInterval: time.Millisecond})
	session := openAgentSession(t, addr, "synthetic-token", "db")
	defer session.close()
	select {
	case <-m.entered:
	case <-time.After(time.Second):
		t.Fatal("renew not entered")
	}
	time.Sleep(time.Until(lease.ExpiresAt) + 100*time.Millisecond)
	if _, err := session.query("SELECT current_user"); err == nil {
		t.Fatal("expired session still executes queries while renewal is stalled")
	}
}

func TestAdversarial_ExpiryBeforeRenewFloor(t *testing.T) {
	lease := &Lease{ID: "review", Username: "review-user", Password: "synthetic", ExpiresAt: time.Now().Add(100 * time.Millisecond), Renewable: true}
	upstream := startFakeUpstream(t, authTrust, "")
	_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: upstream.addr()}}, Leases: &fakeMinter{lease: lease}, MinRenewInterval: time.Second})
	session := openAgentSession(t, addr, "synthetic-token", "db")
	defer session.close()
	time.Sleep(time.Until(lease.ExpiresAt) + 100*time.Millisecond)
	if _, err := session.query("SELECT current_user"); err == nil {
		t.Fatal("expired session still executes queries before minimum renewal interval")
	}
}

func TestAdversarial_LiveBudgetReduction(t *testing.T) {
	b := New("", Options{MaxConns: 10})
	original := &DatabaseService{Addr: "db:5432", MaxConns: 3}
	if !b.acquireUpstreamSlot(original) {
		t.Fatal("initial slot unavailable")
	}
	defer b.releaseUpstreamSlot(original)
	updated := &DatabaseService{Addr: "db:5432", MaxConns: 1}
	if b.acquireUpstreamSlot(updated) {
		b.releaseUpstreamSlot(updated)
		t.Fatal("live max_conns reduction ignored: admitted 2 sessions with updated limit 1")
	}
}

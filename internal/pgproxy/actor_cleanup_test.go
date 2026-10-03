package pgproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
	"github.com/Infisical/agent-vault/internal/store"
)

type actorRecordingMint struct {
	*fakeMinter
	scope   chan AgentScope
	release chan struct{}
}

func (m *actorRecordingMint) Mint(ctx context.Context, scope AgentScope, _ *DatabaseService) (*Lease, error) {
	m.scope <- scope
	select {
	case <-m.release:
	case <-ctx.Done():
	}
	return nil, context.Canceled
}

func (b *Broker) connectionActors() (total int, actors []runtimestatus.Attribution) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, actor := range b.connActors {
		actors = append(actors, actor)
	}
	return len(b.conns), actors
}

func waitForConnections(t *testing.T, b *Broker, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if total, _ := b.connectionActors(); total == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker never reached %d connections", want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A connection is unattributed until its proof authenticates, then belongs to
// exactly that actor and runtime instance, which Mint receives for its record.
func TestBrokerAttributesConnectionToAuthenticatedActor(t *testing.T) {
	m := &actorRecordingMint{fakeMinter: &fakeMinter{}, scope: make(chan AgentScope, 1), release: make(chan struct{})}
	owner := runtimestatus.Attribution{ActorID: "agent-a", WorkloadID: "pod-uid-a"}
	b, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: owner.ActorID, WorkloadID: owner.WorkloadID}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: "unused:5432"}}, Leases: m})

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	waitForConnections(t, b, 1)
	if _, actors := b.connectionActors(); len(actors) != 0 {
		t.Fatalf("unauthenticated connection attributed: %v", actors)
	}

	done := make(chan struct{})
	go func() { defer close(done); connectExpectCode(t, addr, "token", "db") }()
	select {
	case got := <-m.scope:
		if got.ActorID != owner.ActorID || got.WorkloadID != owner.WorkloadID {
			t.Fatalf("mint scope = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mint did not start")
	}
	if total, actors := b.connectionActors(); total != 2 || len(actors) != 1 || actors[0] != owner {
		t.Fatalf("attribution during mint: total=%d actors=%v", total, actors)
	}
	close(m.release)
	<-done
	_ = idle.Close()
	waitForConnections(t, b, 0)
	if _, actors := b.connectionActors(); len(actors) != 0 {
		t.Fatalf("attribution leaked after close: %v", actors)
	}
}

func TestCleanupSnapshotPartitionsByActor(t *testing.T) {
	client, st, _ := durableFixture(t)
	checkCleanupSnapshotPartition(t, client, st)
}

func checkCleanupSnapshotPartition(t *testing.T, client *hashicorp.Client, st *store.SQLStore) {
	t.Helper()
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{RetryInterval: time.Hour, OwnerTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	b := New("127.0.0.1:0", Options{Leases: m})
	b.isListening.Store(true)
	snapshot := CleanupSnapshot(b, m)

	lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault", ActorID: "agent-a", WorkloadID: "pod-a1"}, &DatabaseService{Name: "db", Mount: "database", Role: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []store.DatabaseCleanup{{Accessor: "legacy", Binding: "vault/other"}, {Accessor: "agent-level", Binding: "vault/other", ActorID: "agent-a"}} {
		if err := st.AddDatabaseCleanup(context.Background(), m.owner, record); err != nil {
			t.Fatal(err)
		}
	}
	owned, ownedPeer := net.Pipe()
	pending, pendingPeer := net.Pipe()
	for _, c := range []net.Conn{owned, ownedPeer, pending, pendingPeer} {
		defer c.Close()
	}
	b.mu.Lock()
	b.conns[owned] = struct{}{}
	b.conns[pending] = struct{}{}
	b.connectionGeneration++
	b.mu.Unlock()
	b.attribute(owned, runtimestatus.Attribution{ActorID: "agent-b", WorkloadID: "pod-b1"})

	got, err := snapshot(context.Background())
	if err != nil || !got.Consistent {
		t.Fatalf("snapshot: %+v %v", got, err)
	}
	want := map[runtimestatus.Attribution]runtimestatus.Counts{
		{ActorID: "agent-a", WorkloadID: "pod-a1"}: {UnfinishedCleanup: 1},
		{ActorID: "agent-a"}:                       {UnfinishedCleanup: 1, UnknownCleanup: 1},
		{ActorID: "agent-b", WorkloadID: "pod-b1"}: {ActiveConnections: 1},
	}
	if len(got.Attributed) != len(want) {
		t.Fatalf("attributed = %+v", got.Attributed)
	}
	for owner, counts := range want {
		if got.Attributed[owner] != counts {
			t.Fatalf("attributed = %+v", got.Attributed)
		}
	}
	if got.Unattributed != (runtimestatus.Counts{ActiveConnections: 1, UnfinishedCleanup: 1, UnknownCleanup: 1}) {
		t.Fatalf("unattributed = %+v", got.Unattributed)
	}
	if got.ActiveConnections != 2 || got.UnfinishedCleanup != 3 || got.UnknownCleanup != 2 {
		t.Fatalf("totals changed: %+v", got)
	}
	// An actor the broker has never seen still inherits every unattributed item.
	if got.ForActor("agent-c") != got.Unattributed {
		t.Fatal("unattributed work not charged to an unseen actor")
	}

	if got.ForActor("agent-a") != (runtimestatus.Counts{ActiveConnections: 1, UnfinishedCleanup: 3, UnknownCleanup: 2}) {
		t.Fatalf("agent-a = %+v", got.ForActor("agent-a"))
	}

	b.unregister(pending)
	for _, accessor := range []string{"legacy", "agent-level"} {
		if err := st.DeleteDatabaseCleanup(context.Background(), accessor); err != nil {
			t.Fatal(err)
		}
	}
	if got, err = snapshot(context.Background()); err != nil || got.ForActor("agent-c") != (runtimestatus.Counts{}) || got.ForActor("agent-a").UnfinishedCleanup != 1 {
		t.Fatalf("after unattributed cleared: %+v %v", got, err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	b.unregister(owned)
	if got, err = snapshot(context.Background()); err != nil || len(got.Attributed) != 0 || got.Unattributed != (runtimestatus.Counts{}) {
		t.Fatalf("after cleanup: %+v %v", got, err)
	}
	b.attribute(owned, runtimestatus.Attribution{ActorID: "agent-b", WorkloadID: "pod-b1"})
	if _, actors := b.connectionActors(); len(actors) != 0 {
		t.Fatal("attribution recorded for an unregistered connection")
	}
}

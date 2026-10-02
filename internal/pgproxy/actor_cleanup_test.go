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
	actor   chan string
	release chan struct{}
}

func (m *actorRecordingMint) Mint(ctx context.Context, _, actorID string, _ *DatabaseService) (*Lease, error) {
	m.actor <- actorID
	select {
	case <-m.release:
	case <-ctx.Done():
	}
	return nil, context.Canceled
}

func (b *Broker) connectionActors() (total int, actors []string) {
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
// exactly that actor, and the minted cleanup record is tagged with it.
func TestBrokerAttributesConnectionToAuthenticatedActor(t *testing.T) {
	m := &actorRecordingMint{fakeMinter: &fakeMinter{}, actor: make(chan string, 1), release: make(chan struct{})}
	b, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "agent-a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: "unused:5432"}}, Leases: m})

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
	case got := <-m.actor:
		if got != "agent-a" {
			t.Fatalf("mint actor = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mint did not start")
	}
	if total, actors := b.connectionActors(); total != 2 || len(actors) != 1 || actors[0] != "agent-a" {
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

	lease, err := m.Mint(context.Background(), "vault", "agent-a", &DatabaseService{Name: "db", Mount: "database", Role: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddDatabaseCleanup(context.Background(), m.owner, store.DatabaseCleanup{Accessor: "legacy", Binding: "vault/other"}); err != nil {
		t.Fatal(err)
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
	b.attribute(owned, "agent-b")

	got, err := snapshot(context.Background())
	if err != nil || !got.Consistent {
		t.Fatalf("snapshot: %+v %v", got, err)
	}
	want := map[string]runtimestatus.Counts{"agent-a": {UnfinishedCleanup: 1}, "agent-b": {ActiveConnections: 1}}
	if len(got.Actors) != 2 || got.Actors["agent-a"] != want["agent-a"] || got.Actors["agent-b"] != want["agent-b"] {
		t.Fatalf("actors = %+v", got.Actors)
	}
	if got.Unattributed != (runtimestatus.Counts{ActiveConnections: 1, UnfinishedCleanup: 1, UnknownCleanup: 1}) {
		t.Fatalf("unattributed = %+v", got.Unattributed)
	}
	if got.ActiveConnections != 2 || got.UnfinishedCleanup != 2 || got.UnknownCleanup != 1 {
		t.Fatalf("totals changed: %+v", got)
	}
	// An actor the broker has never seen still inherits every unattributed item.
	if got.ForActor("agent-c") != got.Unattributed {
		t.Fatal("unattributed work not charged to an unseen actor")
	}

	b.unregister(pending)
	if err := st.DeleteDatabaseCleanup(context.Background(), "legacy"); err != nil {
		t.Fatal(err)
	}
	if got, err = snapshot(context.Background()); err != nil || got.ForActor("agent-c") != (runtimestatus.Counts{}) || got.ForActor("agent-a").UnfinishedCleanup != 1 {
		t.Fatalf("after unattributed cleared: %+v %v", got, err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	b.unregister(owned)
	if got, err = snapshot(context.Background()); err != nil || len(got.Actors) != 0 || got.Unattributed != (runtimestatus.Counts{}) {
		t.Fatalf("after cleanup: %+v %v", got, err)
	}
	b.attribute(owned, "agent-b")
	if _, actors := b.connectionActors(); len(actors) != 0 {
		t.Fatal("attribution recorded for an unregistered connection")
	}
}

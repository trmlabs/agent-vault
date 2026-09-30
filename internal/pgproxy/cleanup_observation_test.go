package pgproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type observationJournal struct {
	CleanupJournal
	onRead func()
	fail   bool
}

func (j observationJournal) ListDatabaseCleanup(ctx context.Context) ([]store.DatabaseCleanup, error) {
	if j.onRead != nil {
		j.onRead()
	}
	if j.fail {
		return nil, errors.New("synthetic private journal error")
	}
	return j.CleanupJournal.ListDatabaseCleanup(ctx)
}

func TestCleanupSnapshotTransitions(t *testing.T) {
	client, st, vault := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{RetryInterval: time.Hour, OwnerTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	b := New("127.0.0.1:0", Options{Leases: m})
	b.isListening.Store(true)
	snapshot := CleanupSnapshot(b, m)
	got, err := snapshot(context.Background())
	if err != nil || !got.Healthy || !got.Consistent || got.UnfinishedCleanup != 0 {
		t.Fatalf("empty snapshot: %+v %v", got, err)
	}
	a, z := net.Pipe()
	defer a.Close()
	defer z.Close()
	b.mu.Lock()
	b.conns[a] = struct{}{}
	b.connectionGeneration++
	b.mu.Unlock()
	got, err = snapshot(context.Background())
	if err != nil || got.ActiveConnections != 1 {
		t.Fatalf("active frontend missed: %+v %v", got, err)
	}
	b.unregister(a)
	m.activeMu.Lock()
	m.active["orphan"] = durableLease{}
	m.activeMu.Unlock()
	if _, err := snapshot(context.Background()); err == nil {
		t.Fatal("active lease missing from journal ignored")
	}
	m.activeMu.Lock()
	delete(m.active, "orphan")
	m.activeMu.Unlock()
	if err := st.AddDatabaseCleanup(context.Background(), m.owner, store.DatabaseCleanup{Accessor: "synthetic", Binding: "fixture"}); err != nil {
		t.Fatal(err)
	}
	got, err = snapshot(context.Background())
	if err != nil || got.UnfinishedCleanup != 1 || got.UnknownCleanup != 1 {
		t.Fatalf("unknown missed: %+v %v", got, err)
	}
	if err := st.SetDatabaseCleanupLease(context.Background(), m.owner, "synthetic", "synthetic-lease"); err != nil {
		t.Fatal(err)
	}
	got, err = snapshot(context.Background())
	if err != nil || got.UnfinishedCleanup != 1 || got.UnknownCleanup != 0 {
		t.Fatalf("pending missed: %+v %v", got, err)
	}
	if err := st.DeleteDatabaseCleanup(context.Background(), "synthetic"); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.journal = observationJournal{CleanupJournal: st, onRead: func() { b.mu.Lock(); b.connectionGeneration++; b.mu.Unlock() }}
	m.mu.Unlock()
	got, err = snapshot(context.Background())
	if err != nil || got.Consistent {
		t.Fatal("connection race reported consistent")
	}
	m.mu.Lock()
	m.journal = observationJournal{CleanupJournal: st, fail: true}
	m.mu.Unlock()
	if _, err := snapshot(context.Background()); err == nil {
		t.Fatal("journal error ignored")
	}
	m.mu.Lock()
	m.journal = st
	m.mu.Unlock()
	vault.mu.Lock()
	vault.denyLookup = true
	vault.mu.Unlock()
	if _, err := snapshot(context.Background()); err == nil {
		t.Fatal("revoked Vault login reported healthy")
	}
	vault.mu.Lock()
	vault.denyLookup = false
	vault.mu.Unlock()
	if err := st.ReleaseDatabaseCleanupOwner(context.Background(), m.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(context.Background()); err == nil {
		t.Fatal("lost owner reported healthy")
	}
}

func TestCleanupSnapshotUnavailable(t *testing.T) {
	if _, err := CleanupSnapshot(nil, nil)(context.Background()); err == nil {
		t.Fatal("unconfigured snapshot ready")
	}
	client, st, _ := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	b := New("127.0.0.1:0", Options{Leases: m})
	if _, err := CleanupSnapshot(b, m)(context.Background()); err == nil {
		t.Fatal("nonlistening broker ready")
	}
	b.isListening.Store(true)
	other := New("127.0.0.1:0", Options{})
	other.isListening.Store(true)
	if _, err := CleanupSnapshot(other, m)(context.Background()); err == nil {
		t.Fatal("unrelated cleanup provider accepted")
	}
	m.cancel()
	if _, err := CleanupSnapshot(b, m)(context.Background()); err == nil {
		t.Fatal("expired authority ready")
	}
}

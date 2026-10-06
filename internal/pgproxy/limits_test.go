package pgproxy

import "testing"

// With pooling, client sessions hold no database connection of their own, so
// their caps default to fleet scale; unpooled, each session is a database
// connection, and each database's ceiling comes from its catalog maxConns.
func TestSessionCapDefaultsFollowPooling(t *testing.T) {
	pooled := New("127.0.0.1:0", Options{Pool: &PoolOptions{}})
	if o := pooled.opts; o.MaxConns != 10000 || o.MaxPendingConns != 10000 || o.MaxLeasesPerActor != 1024 || o.MaxLeasesPerAgent != 10000-1024 {
		t.Fatalf("pooled defaults %d %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor, o.MaxLeasesPerAgent)
	}
	if q := (&PoolOptions{}).withDefaults().QueueFactor; q != 200 {
		t.Fatalf("queue factor %d", q)
	}
	if b := (&PoolOptions{}).withDefaults().DefaultBudget; b != 50 {
		t.Fatalf("pool fallback budget %d", b)
	}
	unpooled := New("127.0.0.1:0", Options{})
	if o := unpooled.opts; o.MaxConns != 10000 || o.MaxPendingConns != 10000 || o.MaxLeasesPerActor != 16 || o.DefaultDatabaseConns != 50 {
		t.Fatalf("unpooled defaults %d %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor, o.DefaultDatabaseConns)
	}
	// Explicit settings still win, at any size.
	set := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, MaxConns: 50000, MaxPendingConns: 70000, MaxLeasesPerActor: 4000})
	if o := set.opts; o.MaxConns != 50000 || o.MaxPendingConns != 70000 || o.MaxLeasesPerActor != 4000 {
		t.Fatalf("explicit settings %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor)
	}
}

// Unpooled, a database's ceiling is its catalog maxConns, at any size; only a
// database without one falls back to the default.
func TestUnpooledDatabaseCeilingComesFromTheCatalog(t *testing.T) {
	b := New("127.0.0.1:0", Options{})
	sized := &DatabaseService{Addr: "big.example:5432", MaxConns: 2000}
	unsized := &DatabaseService{Addr: "small.example:5432"}
	for i := 0; i < 2000; i++ {
		if !b.acquireUpstreamSlot(sized) {
			t.Fatalf("refused at %d of 2000", i)
		}
	}
	if b.acquireUpstreamSlot(sized) {
		t.Fatal("past the catalog's maxConns")
	}
	for i := 0; i < 50; i++ {
		if !b.acquireUpstreamSlot(unsized) {
			t.Fatalf("refused at %d of 50", i)
		}
	}
	if b.acquireUpstreamSlot(unsized) {
		t.Fatal("past the fallback for a database without maxConns")
	}
	set := New("127.0.0.1:0", Options{DefaultDatabaseConns: 300})
	for i := 0; i < 300; i++ {
		if !set.acquireUpstreamSlot(unsized) {
			t.Fatalf("refused at %d of an overridden 300", i)
		}
	}
}

// An operator who set MaxConns keeps it as the ceiling for databases without
// maxConns; the pooled budget fallback is separate.
func TestExplicitMaxConnsIsTheUnsizedFallback(t *testing.T) {
	if o := New("127.0.0.1:0", Options{MaxConns: 128}).opts; o.DefaultDatabaseConns != 128 {
		t.Fatalf("unpooled fallback %d, want 128", o.DefaultDatabaseConns)
	}
	if o := New("127.0.0.1:0", Options{MaxConns: 128, DefaultDatabaseConns: 20}).opts; o.DefaultDatabaseConns != 20 {
		t.Fatalf("explicit fallback %d, want 20", o.DefaultDatabaseConns)
	}
	if o := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, MaxConns: 128}).opts; o.DefaultDatabaseConns != 50 {
		t.Fatalf("pooled fallback %d, want 50", o.DefaultDatabaseConns)
	}
}

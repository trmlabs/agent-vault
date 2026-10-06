package pgproxy

import "testing"

// With pooling, client sessions hold no database connection of their own, so
// their caps default to fleet scale; unpooled, each session is a database
// connection and the small defaults protect the database.
func TestSessionCapDefaultsFollowPooling(t *testing.T) {
	pooled := New("127.0.0.1:0", Options{Pool: &PoolOptions{}})
	if o := pooled.opts; o.MaxConns != 10000 || o.MaxPendingConns != 10000 || o.MaxLeasesPerActor != 1024 || o.MaxLeasesPerAgent != 10000-1024 {
		t.Fatalf("pooled defaults %d %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor, o.MaxLeasesPerAgent)
	}
	if q := (&PoolOptions{}).withDefaults().QueueFactor; q != 200 {
		t.Fatalf("queue factor %d", q)
	}
	unpooled := New("127.0.0.1:0", Options{})
	if o := unpooled.opts; o.MaxConns != 50 || o.MaxPendingConns != 512 || o.MaxLeasesPerActor != 16 {
		t.Fatalf("unpooled defaults %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor)
	}
	// Explicit settings still win, at any size.
	set := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, MaxConns: 50000, MaxPendingConns: 70000, MaxLeasesPerActor: 4000})
	if o := set.opts; o.MaxConns != 50000 || o.MaxPendingConns != 70000 || o.MaxLeasesPerActor != 4000 {
		t.Fatalf("explicit settings %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor)
	}
}

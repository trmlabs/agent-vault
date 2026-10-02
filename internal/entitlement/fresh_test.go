package entitlement

import (
	"context"
	"sync"
	"testing"
	"time"
)

// countingSource is a directory whose membership can change, counting asks.
type countingSource struct {
	mu     sync.Mutex
	groups map[string][]string
	asks   int
}

func (s *countingSource) Lookup(_ context.Context, subject string, asked []string) (Person, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asks++
	var member []string
	for _, a := range asked {
		for _, g := range s.groups[subject] {
			if a == g {
				member = append(member, a)
			}
		}
	}
	return Person{ObjectID: "oid", Enabled: true, MemberOf: member}, nil
}

func (s *countingSource) set(subject string, groups ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[subject] = groups
}

func (s *countingSource) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.asks }

var (
	claudePool = Pool{Identity: "claude-session", Ceiling: "T2"}
	t1Entry    = Entry{Tier: "T1", Requires: []string{"g1"}}
	t2Entry    = Entry{Tier: "T2", Requires: []string{"g2"}}
	carol      = Requester{Kind: "person", Subject: "sso|carol"}
)

func TestT2AdmissionAlwaysAsksTheDirectory(t *testing.T) {
	src := &countingSource{groups: map[string][]string{"sso|carol": {"g1", "g2"}}}
	cache := &Cache{Source: src, TTL: time.Minute}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed {
			t.Fatalf("T2 admission %d refused: %s", i, d.Outcome)
		}
	}
	if src.count() != 3 {
		t.Fatalf("three T2 admissions asked the directory %d times, want 3", src.count())
	}
	// T1 admissions and T2 rechecks may use the cache.
	before := src.count()
	Decide(ctx, cache, claudePool, t1Entry, carol)
	Decide(ctx, cache, claudePool, t1Entry, carol)
	Decide(WithRecheck(ctx), cache, claudePool, t2Entry, carol)
	if got := src.count() - before; got != 1 {
		t.Fatalf("two T1 admissions and a T2 recheck asked %d times, want 1 (the first T1)", got)
	}
	// Removal takes effect on the very next T2 admission, inside the TTL.
	src.set("sso|carol", "g1")
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); d.Allowed || d.Outcome != "not_entitled" {
		t.Fatalf("T2 admission after removal: %+v", d)
	}
}

func TestRecheckRefusalPurgesThePerson(t *testing.T) {
	src := &countingSource{groups: map[string][]string{"sso|carol": {"g1", "g2"}}}
	cache := &Cache{Source: src, TTL: time.Minute}
	ctx := context.Background()
	if d := Decide(ctx, cache, claudePool, t1Entry, carol); !d.Allowed {
		t.Fatal("T1 admission refused")
	}
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed {
		t.Fatal("T2 admission refused")
	}
	// carol leaves both groups. A T2 admission stores the fresh refusal; the
	// recheck reads it and refuses, purging carol, so her cached T1 answer
	// (still inside its TTL) is gone too.
	src.set("sso|carol")
	Decide(ctx, cache, claudePool, t2Entry, carol)
	if d := Decide(WithRecheck(ctx), cache, claudePool, t2Entry, carol); d.Allowed {
		t.Fatal("recheck allowed a removed person")
	}
	if d := Decide(ctx, cache, claudePool, t1Entry, carol); d.Allowed || d.Outcome != "not_entitled" {
		t.Fatalf("T1 after a recheck refusal rode the cache: %+v", d)
	}
	// Without a refusal nothing is purged: another person's answer stays cached.
	src.set("sso|dave", "g1")
	dave := Requester{Kind: "person", Subject: "sso|dave"}
	Decide(ctx, cache, claudePool, t1Entry, dave)
	before := src.count()
	Decide(WithRecheck(ctx), cache, claudePool, t1Entry, dave)
	if src.count() != before {
		t.Fatal("an allowed recheck dropped the cache")
	}
}

// gatedSource holds every lookup until released, counting asks.
type gatedSource struct {
	countingSource
	entered chan struct{}
	release chan struct{}
}

func (s *gatedSource) Lookup(ctx context.Context, subject string, asked []string) (Person, error) {
	s.entered <- struct{}{}
	<-s.release
	return s.countingSource.Lookup(ctx, subject, asked)
}

// A worker looping on a T2 entry asks the directory once per request; past
// the person's budget it is refused before the directory is asked, after a
// short window in which the latest answer stands. Other people keep theirs.
func TestT2LookupsHaveAPerPersonBudget(t *testing.T) {
	src := &countingSource{groups: map[string][]string{"sso|carol": {"g2"}, "sso|dave": {"g2"}}}
	now := time.Now()
	cache := &Cache{Source: src, TTL: time.Minute, LookupsPerMinute: 3, Now: func() time.Time { return now }}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed {
			t.Fatalf("T2 admission %d refused: %s", i, d.Outcome)
		}
	}
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed || src.count() != 3 {
		t.Fatalf("over budget, the answer just given should stand: %+v asks=%d", d, src.count())
	}
	now = now.Add(DefaultRecentAnswer)
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); d.Allowed || d.Outcome != "entitlement_rate_limited" || src.count() != 3 {
		t.Fatalf("over budget: %+v asks=%d", d, src.count())
	}
	if d := Decide(ctx, cache, claudePool, t2Entry, Requester{Kind: "person", Subject: "sso|dave"}); !d.Allowed {
		t.Fatalf("one person's budget refused another: %s", d.Outcome)
	}
	now = now.Add(time.Minute)
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed || src.count() != 5 {
		t.Fatalf("budget not restored after a minute: %+v asks=%d", d, src.count())
	}
}

// Concurrent fresh lookups of one question share one directory call, and an
// asker that gives up does not end it for the others.
func TestConcurrentFreshLookupsShareOneCall(t *testing.T) {
	src := &gatedSource{countingSource: countingSource{groups: map[string][]string{"sso|carol": {"g2"}}},
		entered: make(chan struct{}, 8), release: make(chan struct{})}
	cache := &Cache{Source: src, TTL: time.Minute}
	leader, cancel := context.WithCancel(context.Background())
	results := make(chan Decision, 6)
	go func() { results <- Decide(leader, cache, claudePool, t2Entry, carol) }()
	<-src.entered
	for i := 0; i < 5; i++ {
		go func() { results <- Decide(context.Background(), cache, claudePool, t2Entry, carol) }()
	}
	time.Sleep(200 * time.Millisecond) // let the joiners reach the flight
	cancel()
	close(src.release)
	for i := 0; i < 6; i++ {
		if d := <-results; !d.Allowed {
			t.Fatalf("shared lookup refused: %s", d.Outcome)
		}
	}
	if src.count() != 1 {
		t.Fatalf("six concurrent T2 admissions asked %d times, want 1", src.count())
	}
}

// A purge while a lookup is in flight wins: the older answer does not refill
// the cache, so the next lookup asks the directory.
func TestPurgeDuringALookupIsNotUndone(t *testing.T) {
	src := &gatedSource{countingSource: countingSource{groups: map[string][]string{"sso|carol": {"g1"}}},
		entered: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	cache := &Cache{Source: src, TTL: time.Minute}
	done := make(chan Decision, 1)
	go func() { done <- Decide(context.Background(), cache, claudePool, t1Entry, carol) }()
	<-src.entered
	cache.Purge(carol.Subject)
	src.release <- struct{}{}
	<-done
	src.release <- struct{}{}
	go func() { done <- Decide(context.Background(), cache, claudePool, t1Entry, carol) }()
	select {
	case <-src.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("a lookup from before the purge refilled the cache")
	}
	<-done
}

// A fresh answer that refuses forgets the person, like a refused recheck: a
// cached T1 answer inside its TTL does not survive a T2 refusal.
func TestFreshRefusalPurgesThePerson(t *testing.T) {
	src := &countingSource{groups: map[string][]string{"sso|carol": {"g1"}}}
	cache := &Cache{Source: src, TTL: time.Minute}
	ctx := context.Background()
	if d := Decide(ctx, cache, claudePool, t1Entry, carol); !d.Allowed {
		t.Fatal("T1 admission refused")
	}
	src.set("sso|carol")
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); d.Allowed {
		t.Fatal("T2 admission allowed a non-member")
	}
	if d := Decide(ctx, cache, claudePool, t1Entry, carol); d.Allowed || d.Outcome != "not_entitled" {
		t.Fatalf("T1 after a fresh refusal rode the cache: %+v", d)
	}
}

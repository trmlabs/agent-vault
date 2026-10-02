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
	// Removal takes effect on the very next T2 admission, inside the TTL.
	src.set("sso|carol", "g1")
	if d := Decide(ctx, cache, claudePool, t2Entry, carol); d.Allowed || d.Outcome != "not_entitled" {
		t.Fatalf("T2 admission after removal: %+v", d)
	}
	// T1 admissions and T2 rechecks may use the cache.
	before := src.count()
	Decide(ctx, cache, claudePool, t1Entry, carol)
	Decide(ctx, cache, claudePool, t1Entry, carol)
	Decide(WithRecheck(ctx), cache, claudePool, t2Entry, carol)
	if got := src.count() - before; got != 1 {
		t.Fatalf("two T1 admissions and a T2 recheck asked %d times, want 1 (the first T1)", got)
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

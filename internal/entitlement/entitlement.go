// Package entitlement decides whether an agent's request may use a catalog
// entry: the lesser of the pool's tier ceiling and, for human sessions, the
// verified person's live group membership. Every lookup error refuses.
package entitlement

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxCacheTTL bounds how long a person's groups are trusted. Offboarding takes
// effect within it, because the runner's session tokens cannot be revoked.
const MaxCacheTTL = 5 * time.Minute

// Person is one directory user and the subset of asked groups it belongs to.
type Person struct {
	ObjectID string
	Enabled  bool
	MemberOf []string // only groups that were asked about
}

// Source looks a person up by SSO subject and checks membership of groups.
type Source interface {
	Lookup(ctx context.Context, subject string, groups []string) (Person, error)
}

type cached struct {
	person  Person
	fetched time.Time
}

// Cache wraps a Source with a short per-person, per-group-set cache.
type Cache struct {
	Source Source
	TTL    time.Duration
	Now    func() time.Time

	mu      sync.Mutex
	entries map[string]cached
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Lookup returns the person and how old the answer is. Errors are never cached.
func (c *Cache) Lookup(ctx context.Context, subject string, groups []string) (Person, time.Duration, error) {
	if c == nil || c.Source == nil {
		return Person{}, 0, errors.New("no entitlement source configured")
	}
	ttl := c.TTL
	if ttl <= 0 || ttl > MaxCacheTTL {
		ttl = MaxCacheTTL
	}
	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	key := subject + "\x00" + strings.Join(sorted, ",")
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.fetched) < ttl {
		c.mu.Unlock()
		return e.person, now.Sub(e.fetched), nil
	}
	c.mu.Unlock()
	person, err := c.Source.Lookup(ctx, subject, sorted)
	if err != nil {
		return Person{}, 0, err
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]cached{}
	}
	if len(c.entries) > 10000 {
		c.entries = map[string]cached{}
	}
	c.entries[key] = cached{person: person, fetched: now}
	c.mu.Unlock()
	return person, 0, nil
}

// Tier ranks catalog tiers. T0 is readable by everyone allowed on the pool.
func Tier(t string) (int, error) {
	switch t {
	case "", "T0":
		return 0, nil
	case "T1":
		return 1, nil
	case "T2":
		return 2, nil
	}
	return 0, fmt.Errorf("unknown tier %q", t)
}

// Pool is what the decision needs from a catalog pool.
type Pool struct {
	Identity     string // "none" (default), "claude-session" or "workload"
	Ceiling      string // highest tier the pool may reach
	Entitlements []string
}

// Entry is what the decision needs from a catalog entry.
type Entry struct {
	Tier     string
	Requires []string
}

// Requester is the verified identity behind the request.
type Requester struct {
	Kind    string // "person", "agent", "workload" or "none"
	Subject string
}

// Decision records why a request was allowed or refused, for the audit row.
type Decision struct {
	Allowed  bool
	Outcome  string // fixed code
	Tier     string
	Groups   []string // groups checked
	ObjectID string
	CacheAge time.Duration
}

// Decide applies the lesser of the pool ceiling and the requester's entitlements.
func Decide(ctx context.Context, cache *Cache, pool Pool, entry Entry, who Requester) Decision {
	tier := entry.Tier
	if tier == "" {
		tier = "T0"
	}
	d := Decision{Tier: tier, Groups: append([]string(nil), entry.Requires...)}
	want, err1 := Tier(entry.Tier)
	ceiling, err2 := Tier(pool.Ceiling)
	if err1 != nil || err2 != nil {
		d.Outcome = "entitlement_config"
		return d
	}
	if want > ceiling {
		d.Outcome = "pool_ceiling"
		return d
	}
	if want == 0 {
		d.Allowed, d.Outcome = true, "t0"
		return d
	}
	switch pool.Identity {
	case "workload":
		if want >= 2 || !subset(entry.Requires, pool.Entitlements) {
			d.Outcome = "workload_not_entitled"
			return d
		}
		d.Allowed, d.Outcome = true, "workload_entitled"
		return d
	case "claude-session":
	default:
		d.Outcome = "no_identity"
		return d
	}
	if who.Kind != "person" || who.Subject == "" {
		d.Outcome = "no_person"
		return d
	}
	if len(entry.Requires) == 0 {
		d.Outcome = "entitlement_config"
		return d
	}
	person, age, err := cache.Lookup(ctx, who.Subject, entry.Requires)
	d.CacheAge = age
	if err != nil {
		d.Outcome = "entitlement_unavailable"
		return d
	}
	d.ObjectID = person.ObjectID
	if !person.Enabled {
		d.Outcome = "account_disabled"
		return d
	}
	if !subset(entry.Requires, person.MemberOf) {
		d.Outcome = "not_entitled"
		return d
	}
	d.Allowed, d.Outcome = true, "entitled"
	return d
}

func subset(want, have []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

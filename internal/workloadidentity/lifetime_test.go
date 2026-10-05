package workloadidentity

import (
	"context"
	"testing"
	"time"
)

// The last good keys stand through failed refetches for at most a day, in
// every trust domain.
func TestLastGoodKeysExpireAfterADay(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	r := withDomains(t, f, rc.td)
	ctx := context.Background()
	if _, _, err := r.verifyLocally(ctx, f.token(f.c), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.verifyLocally(ctx, rc.token(rc.claims()), false); err != nil {
		t.Fatal(err)
	}
	f.jwksFail.Store(true)
	rc.fail.Store(true)
	for _, d := range r.domains {
		d.keys.mu.Lock()
		d.keys.fetched = time.Now().Add(-jwksMaxStale + time.Minute)
		d.keys.attempted = time.Now().Add(-jwksRefetchBackoff - time.Second)
		d.keys.mu.Unlock()
	}
	// Under a day old: kept.
	if _, _, err := r.verifyLocally(ctx, f.token(f.c), true); err != nil {
		t.Fatalf("own keys under a day dropped: %v", err)
	}
	if _, _, err := r.verifyLocally(ctx, rc.token(rc.claims()), true); err != nil {
		t.Fatalf("remote keys under a day dropped: %v", err)
	}
	for _, d := range r.domains {
		d.keys.mu.Lock()
		d.keys.fetched = time.Now().Add(-jwksMaxStale - time.Minute)
		d.keys.mu.Unlock()
	}
	if _, _, err := r.verifyLocally(ctx, f.token(f.c), true); err == nil {
		t.Fatal("own keys over a day old still verify")
	}
	if _, _, err := r.verifyLocally(ctx, rc.token(rc.claims()), true); err == nil {
		t.Fatal("remote keys over a day old still verify")
	}
}

// Each trust domain bounds token lifetime by its own limit and requires the
// Pod claim.
func TestEachTrustDomainBoundsItsTokens(t *testing.T) {
	f := setupPool(t)
	rc := newRemoteCluster(t)
	rc.td.MaxTokenLifetimeSeconds = 600
	r := withDomains(t, f, rc.td)
	ctx := context.Background()
	type domainCase struct {
		name  string
		base  claims
		limit int64
		sign  func(claims) string
	}
	for _, d := range []domainCase{
		{"own cluster", f.c, f.r.config.MaxTokenLifetimeSeconds, f.token},
		{"remote", rc.claims(), 600, rc.token},
	} {
		exact := d.base
		exact.Issued = time.Now().Unix() - 1
		exact.Expires = exact.Issued + d.limit
		if _, _, err := r.verifyLocally(ctx, d.sign(exact), false); err != nil {
			t.Errorf("%s: a token of exactly the limit refused: %v", d.name, err)
		}
		over := exact
		over.Expires++
		if _, _, err := r.verifyLocally(ctx, d.sign(over), false); err == nil {
			t.Errorf("%s: a token one second over the limit accepted", d.name)
		}
		podless := exact
		podless.Kubernetes.Pod.Name, podless.Kubernetes.Pod.UID = "", ""
		if _, _, err := r.verifyLocally(ctx, d.sign(podless), false); err == nil {
			t.Errorf("%s: a token with no Pod claim accepted", d.name)
		}
	}
}

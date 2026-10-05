package entitlement

import (
	"context"
	"testing"
)

// A pool at the external ceiling is refused even a T0 entry.
func TestExternalCeilingReachesNothing(t *testing.T) {
	d := Decide(context.Background(), &Cache{}, Pool{Ceiling: "external"}, Entry{}, Requester{Kind: "none"})
	if d.Allowed || d.Outcome != "pool_external" {
		t.Fatalf("got %v %q", d.Allowed, d.Outcome)
	}
}

package pgproxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sessionResolver admits while the relayed session token equals want, and
// records what each call saw.
type sessionResolver struct {
	svc  *DatabaseService
	want atomic.Value // string
	mu   sync.Mutex
	seen []string
}

func (r *sessionResolver) ResolveDatabase(ctx context.Context, _ AgentScope, _ string) (*DatabaseService, error) {
	got := Session(ctx)
	r.mu.Lock()
	r.seen = append(r.seen, got)
	r.mu.Unlock()
	if want, _ := r.want.Load().(string); got != want || got == "" {
		RecordRequester(ctx, Requester{Kind: "person", Subject: "user_1", Tier: "T1", Decision: "not_entitled"})
		return nil, &RefusedError{Outcome: "not_entitled"}
	}
	RecordRequester(ctx, Requester{Kind: "person", Subject: "user_1", Tier: "T1", Decision: "entitled"})
	return r.svc, nil
}

func (r *sessionResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func sessionBroker(t *testing.T, r *sessionResolver, audit ...*recordingAudit) string {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	r.svc = &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}
	opts := Options{Auth: &fakePeerAuth{}, Databases: r, Leases: &fakeMinter{lease: lease},
		TrustProxyHeader: true, AuthorizationInterval: 50 * time.Millisecond}
	if len(audit) > 0 {
		opts.Audit = audit[0]
	}
	_, addr := startBroker(t, opts)
	return addr
}

const runnerToken = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.c2ln"

func TestSessionPreambleReachesTheResolverOnAdmissionAndRecheck(t *testing.T) {
	r := &sessionResolver{}
	r.want.Store(runnerToken)
	addr := sessionBroker(t, r)
	conn, err := openSession(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+"\n")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, 2*time.Second, func() bool { return len(r.calls()) >= 2 }, "no recheck ran")
	for _, got := range r.calls() {
		if got != runnerToken {
			t.Fatalf("resolver saw session %q, want the relayed token", got)
		}
	}
}

func TestSessionRefusalIsAnAuthorizationError(t *testing.T) {
	r := &sessionResolver{}
	r.want.Store("another")
	audit := &recordingAudit{}
	addr := sessionBroker(t, r, audit)
	if conn, err := openSession(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+"\n"); err == nil {
		conn.Close()
		t.Fatal("a refused requester was admitted")
	} else if !strings.Contains(err.Error(), "42501") || !strings.Contains(err.Error(), "not_entitled") {
		t.Fatalf("refusal = %v, want 42501 naming the decision", err)
	}
	events := audit.recorded()
	if len(events) != 1 {
		t.Fatalf("audit events %+v", events)
	}
	if e := events[0]; e.Outcome != "not_entitled" || e.Requester != "user_1" || e.RequesterKind != "person" || e.Tier != "T1" || e.Decision != "not_entitled" {
		t.Fatalf("refusal audit %+v", e)
	}
}

func TestNoPreambleMeansNoSession(t *testing.T) {
	r := &sessionResolver{}
	addr := sessionBroker(t, r)
	if conn, err := openSession(t, addr, header("10.244.0.9")); err == nil {
		conn.Close()
		t.Fatal("admitted without a session")
	}
	if calls := r.calls(); len(calls) != 1 || calls[0] != "" {
		t.Fatalf("resolver saw %q, want one call with no session", calls)
	}
}

func TestRecheckEndsTheSessionWhenTheDecisionChanges(t *testing.T) {
	r := &sessionResolver{}
	r.want.Store(runnerToken)
	addr := sessionBroker(t, r)
	conn, err := openSession(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+"\n")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r.want.Store("revoked")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("session survived a refused recheck")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("session was not ended at the recheck")
	}
}

func TestMalformedPreambleIsRefused(t *testing.T) {
	r := &sessionResolver{}
	addr := sessionBroker(t, r)
	for name, line := range map[string]string{
		"empty":     "GHSESS1 \n",
		"bad bytes": "GHSESS1 a b\n",
		"oversized": "GHSESS1 " + strings.Repeat("a", maxSessionBytes+1) + "\n",
	} {
		if conn, err := openSession(t, addr, header("10.244.0.9")+line); err == nil {
			conn.Close()
			t.Fatalf("%s: a malformed preamble was admitted", name)
		}
	}
	if len(r.calls()) != 0 {
		t.Fatal("a malformed preamble reached the resolver")
	}
}

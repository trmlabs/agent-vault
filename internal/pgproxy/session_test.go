package pgproxy

import (
	"context"
	"fmt"
	"log/slog"
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
	if e := events[0]; e.Outcome != "not_entitled" || e.Binding != "vault/appdb" || e.Requester != "user_1" || e.RequesterKind != "person" || e.Tier != "T1" || e.Decision != "not_entitled" {
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

func TestStalledPreambleIsDroppedAtTheStartupDeadline(t *testing.T) {
	r := &sessionResolver{}
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	r.svc = &DatabaseService{Name: "analytics", Addr: upstream.addr()}
	_, addr := startBroker(t, Options{Auth: &fakePeerAuth{}, Databases: r, Leases: &fakeMinter{lease: lease},
		TrustProxyHeader: true, StartupTimeout: 200 * time.Millisecond})
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A prefix and part of a token, then nothing: no newline ever arrives.
	if _, err := conn.Write([]byte(header("10.244.0.9") + "GHSESS1 eyJhbGci")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("broker answered a stalled preamble")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("broker held a stalled preamble open past its startup deadline")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("closed after %v", waited)
	}
	if len(r.calls()) != 0 {
		t.Fatal("a stalled preamble reached the resolver")
	}
}

func TestSessionTokenNeverReachesLogsErrorsOrAudit(t *testing.T) {
	var logs strings.Builder
	var mu sync.Mutex
	r := &sessionResolver{}
	r.want.Store("another")
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	r.svc = &DatabaseService{Name: "analytics", Addr: upstream.addr()}
	audit := &recordingAudit{}
	_, addr := startBroker(t, Options{Auth: &fakePeerAuth{}, Databases: r, Leases: &fakeMinter{lease: lease}, Audit: audit,
		TrustProxyHeader: true, Logger: slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			return logs.Write(p)
		}), &slog.HandlerOptions{Level: slog.LevelDebug}))})
	_, err := openSession(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+"\n")
	if err == nil {
		t.Fatal("refused requester admitted")
	}
	_, _ = openSession(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+" trailing\n")
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	text := logs.String()
	mu.Unlock()
	signature := runnerToken[strings.LastIndex(runnerToken, ".")+1:]
	if strings.Contains(text, signature) || strings.Contains(err.Error(), signature) {
		t.Fatal("the session token reached a log line or a client error")
	}
	for _, e := range audit.recorded() {
		if strings.Contains(fmt.Sprintf("%+v", e), signature) {
			t.Fatal("the session token reached the audit trail")
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

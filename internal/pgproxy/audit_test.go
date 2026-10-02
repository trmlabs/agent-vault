package pgproxy

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

type recordingAudit struct {
	mu        sync.Mutex
	events    []auditchain.Event
	admitErr  error
	failEvent string
}

func (a *recordingAudit) Admit() error { a.mu.Lock(); defer a.mu.Unlock(); return a.admitErr }

func (a *recordingAudit) Record(e auditchain.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Event == a.failEvent {
		return errors.New("audit write failed")
	}
	a.events = append(a.events, e)
	return nil
}

func (a *recordingAudit) recorded() []auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditchain.Event(nil), a.events...)
}

func auditedBroker(t *testing.T, audit *recordingAudit, minter *fakeMinter, upstreamAddr string, authErr error) string {
	t.Helper()
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}, err: authErr},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstreamAddr, Mount: "database", Role: "readonly"}},
		Leases:    minter,
		Audit:     audit,
	})
	return addr
}

// A served session leaves exactly one open and one close row, attributed to
// the verified pool, Pod and binding, and never to a credential.
func TestBrokerAuditsSessionLifecycle(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &recordingAudit{}
	addr := auditedBroker(t, audit, &fakeMinter{lease: lease}, upstream.addr(), nil)
	if _, err := runAgentQuery(t, addr, "agent-vault-token-xyz", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(audit.recorded()) == 2 }, "session close row")
	got := audit.recorded()
	if got[0].Event != auditchain.EventSessionOpen || got[1].Event != auditchain.EventSessionClose || got[0].Session == "" || got[0].Session != got[1].Session {
		t.Fatalf("lifecycle rows: %+v", got)
	}
	for _, e := range got {
		if e.Pool != "pool-agent" || e.Agent != "agent-uuid-1" || e.PodUID != "pod-uid-1" || e.Binding != "vault-1/analytics" {
			t.Fatalf("attribution: %+v", e)
		}
		for _, secret := range []string{lease.Password, lease.Username, lease.ID, "agent-vault-token-xyz"} {
			if strings.Contains(e.Session+e.Outcome+e.Requester, secret) {
				t.Fatal("credential material in audit row")
			}
		}
	}
}

// An unwritable or overdue trail refuses before any credential is minted.
func TestBrokerRefusesSessionWhenAuditUnavailable(t *testing.T) {
	minter := &fakeMinter{lease: newLease()}
	audit := &recordingAudit{admitErr: auditchain.ErrCheckpointOverdue}
	addr := auditedBroker(t, audit, minter, "unused:5432", nil)
	if _, err := runAgentQuery(t, addr, "token", "appdb", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("session admitted without audit: %v", err)
	}
	if minter.mintCallCount() != 0 {
		t.Fatal("credential minted while audit unavailable")
	}
	if got := audit.recorded(); len(got) != 1 || got[0].Event != auditchain.EventDenied || got[0].Outcome != "audit_unavailable" || got[0].Agent != "agent-uuid-1" {
		t.Fatalf("refusal rows: %+v", got)
	}
}

// If the session row cannot be written, no query runs and the lease is revoked.
func TestBrokerRevokesWhenSessionRowFails(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	minter := &fakeMinter{lease: lease}
	audit := &recordingAudit{failEvent: auditchain.EventSessionOpen}
	addr := auditedBroker(t, audit, minter, upstream.addr(), nil)
	if _, err := runAgentQuery(t, addr, "token", "appdb", "SELECT 1"); err == nil {
		t.Fatal("query ran without a session row")
	}
	waitFor(t, 2*time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "lease revoked")
	for _, e := range audit.recorded() {
		if e.Event == auditchain.EventSessionClose {
			t.Fatal("close row for a session that never opened")
		}
	}
}

func TestBrokerAuditsDenials(t *testing.T) {
	audit := &recordingAudit{}
	addr := auditedBroker(t, audit, &fakeMinter{mintErr: errors.New("vault down")}, "unused:5432", nil)
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	unauth := &recordingAudit{}
	addr = auditedBroker(t, unauth, &fakeMinter{}, "unused:5432", errors.New("bad token"))
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	if got := audit.recorded(); len(got) != 1 || got[0].Outcome != "credential" || got[0].Binding != "vault-1/analytics" {
		t.Fatalf("mint denial: %+v", got)
	}
	if got := unauth.recorded(); len(got) != 1 || got[0].Outcome != "authentication" || got[0].Pool != "" || got[0].PodUID != "" {
		t.Fatalf("authentication denial: %+v", got)
	}
}

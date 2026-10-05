package pgproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Every close the broker starts itself names its reason to the client, on
// both paths, so none looks like a crashed backend.

func noticeUpstreamWithTransactions(t *testing.T) *fakeUpstream {
	t.Helper()
	up := startFakeUpstream(t, authTrust, "")
	up.mu.Lock()
	up.transactions = true
	up.mu.Unlock()
	return up
}

func wantNotice(t *testing.T, s *agentSession, code, reason string) {
	t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if gotCode, gotReason := readCloseNotice(t, s.fe); gotCode != code || gotReason != reason {
		t.Fatalf("session ended with %q %q, want %q %q", gotCode, gotReason, code, reason)
	}
}

func TestUnpooledCloseNotices(t *testing.T) {
	svc := func(up *fakeUpstream) *fakeResolver {
		return &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr(), Mount: "database", Role: "readonly", SSLMode: "disable"}}
	}
	t.Run("authorization recheck", func(t *testing.T) {
		up := startFakeUpstream(t, authTrust, "")
		var revoked atomic.Bool
		_, addr := startBroker(t, Options{AuthorizationInterval: 10 * time.Millisecond, Databases: svc(up), Leases: &fakeMinter{lease: newLease()},
			Auth: authFunc(func(context.Context, string, string) (*AgentScope, error) {
				if revoked.Load() {
					return nil, errors.New("revoked")
				}
				return &AgentScope{VaultID: "v", ActorID: "a"}, nil
			})})
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		revoked.Store(true)
		wantNotice(t, s, "08006", "authorization_ended")
	})
	t.Run("credential expiry", func(t *testing.T) {
		up := startFakeUpstream(t, authTrust, "")
		lease := &Lease{ID: "lease-exp", Username: "v-exp", Password: "pw", ExpiresAt: time.Now().Add(500 * time.Millisecond)}
		_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: svc(up), Leases: &fakeMinter{lease: lease}})
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		wantNotice(t, s, "08006", "credential_expired")
	})
	t.Run("Pod deadline", func(t *testing.T) {
		up := startFakeUpstream(t, authTrust, "")
		_, addr := startBroker(t, Options{Databases: svc(up), Leases: &fakeMinter{lease: newLease()},
			Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a", NotAfter: time.Now().Add(400 * time.Millisecond)}}})
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		wantNotice(t, s, "08006", "deadline")
	})
	for _, inTransaction := range []bool{false, true} {
		name, code, reason := "shutdown between transactions", "57P01", "restarting"
		if inTransaction {
			name, code, reason = "shutdown inside a transaction", "08006", "restart_cut"
		}
		t.Run(name, func(t *testing.T) {
			up := noticeUpstreamWithTransactions(t)
			b, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: svc(up), Leases: &fakeMinter{lease: newLease()}})
			s := openAgentSession(t, addr, "token", "db")
			defer s.close()
			if _, err := s.query("SELECT 1"); err != nil {
				t.Fatal(err)
			}
			if inTransaction {
				if _, err := s.query("BEGIN"); err != nil {
					t.Fatal(err)
				}
			}
			done := shutdownBroker(b, 5*time.Second)
			wantNotice(t, s, code, reason)
			<-done
		})
	}
}

func TestPooledCloseNotices(t *testing.T) {
	pooled := func(t *testing.T, auth AgentAuthenticator, audit AuditTrail) (*Broker, string) {
		t.Helper()
		up := noticeUpstreamWithTransactions(t)
		return startBroker(t, Options{Auth: auth, AuthorizationInterval: 10 * time.Millisecond, Audit: audit,
			Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}},
			Leases:    &fakeMinter{lease: newLease()}, Pool: &PoolOptions{QueueFactor: 20}})
	}
	scope := &AgentScope{VaultID: "v", ActorID: "a", WorkloadID: "pod-1", Pool: "cursor"}
	t.Run("authorization recheck", func(t *testing.T) {
		var revoked atomic.Bool
		_, addr := pooled(t, authFunc(func(context.Context, string, string) (*AgentScope, error) {
			if revoked.Load() {
				return nil, errors.New("revoked")
			}
			return scope, nil
		}), nil)
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		revoked.Store(true)
		wantNotice(t, s, "08006", "authorization_ended")
	})
	t.Run("server connection lost", func(t *testing.T) {
		_, addr := pooled(t, &fakeAuth{scope: scope}, nil)
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		if _, err := s.query("BEGIN"); err != nil {
			t.Fatal(err)
		}
		s.fe.Send(&pgproto3.Query{String: "DROP BACKEND"})
		if err := s.fe.Flush(); err != nil {
			t.Fatal(err)
		}
		wantNotice(t, s, "08006", "upstream")
	})
	t.Run("credential expiry", func(t *testing.T) {
		up := noticeUpstreamWithTransactions(t)
		lease := &Lease{ID: "lease-exp", Username: "v-exp", Password: "pw", ExpiresAt: time.Now().Add(2500 * time.Millisecond)}
		_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: scope}, Leases: &fakeMinter{lease: lease}, Pool: &PoolOptions{QueueFactor: 20},
			Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}}})
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		// An open transaction keeps the server connection on the credential
		// until the pool closes it at expiry.
		if _, err := s.query("BEGIN"); err != nil {
			t.Fatal(err)
		}
		wantNotice(t, s, "08006", "credential_expired")
	})
	t.Run("audit trail failure", func(t *testing.T) {
		audit := &failingAudit{failed: make(chan struct{})}
		_, addr := pooled(t, &fakeAuth{scope: scope}, audit)
		s := openAgentSession(t, addr, "token", "db")
		defer s.close()
		if _, err := s.query("SELECT 1"); err != nil {
			t.Fatal(err)
		}
		close(audit.failed)
		wantNotice(t, s, "08004", "audit_unavailable")
	})
}

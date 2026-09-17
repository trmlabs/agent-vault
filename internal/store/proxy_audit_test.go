package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProxyAuditWriteFailuresAreAtomic(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	r := ProxyAudit{RequestID: "request-1", VaultID: "vault", ActorType: "workload", ActorID: "actor", Destination: "example.test", Service: "service", Method: "GET", Decision: "allow"}
	// Simulate a failure after the statement has touched storage. Transaction
	// rollback must leave no acknowledged attempt, even with an AFTER trigger.
	_, err := s.db.Exec(`CREATE TRIGGER fail_audit_insert AFTER INSERT ON credential_proxy_audit BEGIN SELECT RAISE(ABORT,'injected storage failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProxyAudit(ctx, r); err == nil {
		t.Fatal("failed insert acknowledged")
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM credential_proxy_audit`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial insert: %d %v", n, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_audit_insert`); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProxyAudit(ctx, r); err != nil {
		t.Fatal(err)
	}
	var syncMode int
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&syncMode); err != nil || syncMode != 2 {
		t.Fatalf("non-durable SQLite mode %d: %v", syncMode, err)
	}
	_, err = s.db.Exec(`CREATE TRIGGER fail_audit_finish AFTER UPDATE ON credential_proxy_audit BEGIN SELECT RAISE(ABORT,'injected storage failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, r.RequestID, "completed", 200); err == nil {
		t.Fatal("failed finish acknowledged")
	}
	saved, err := s.GetProxyAudit(ctx, r.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Outcome != "unknown" || saved.Status != 0 || saved.FinishedAt != nil {
		t.Fatalf("partial finish: %+v", saved)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_audit_finish`); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, r.RequestID, "completed", 200); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, r.RequestID, "denied", 403); err == nil {
		t.Fatal("completed outcome overwritten")
	}
	if err := s.CompleteProxyAudit(ctx, "missing", "completed", 200); err == nil {
		t.Fatal("nonexistent outcome acknowledged")
	}
}

func TestProxyAuditCancellationIsNotAcknowledged(t *testing.T) {
	s := openTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.InsertProxyAudit(ctx, ProxyAudit{RequestID: "cancelled", Decision: "allow"}); err == nil {
		t.Fatal("cancelled attempt acknowledged")
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM credential_proxy_audit`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cancelled insert: %d %v", n, err)
	}
}

// Exit without closing the SQL connection to model process loss after the
// acknowledged attempt and before any final outcome write.
func TestProxyAuditAbruptProcessExit(t *testing.T) {
	const envKey = "AGENT_VAULT_AUDIT_CRASH_TEST_DB"
	if path := os.Getenv(envKey); path != "" {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.InsertProxyAudit(context.Background(), ProxyAudit{RequestID: "crash-attempt", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestProxyAuditAbruptProcessExit$")
	child.Env = append(os.Environ(), envKey+"="+path)
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child process: %v %s", err, out)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.GetProxyAudit(context.Background(), "crash-attempt")
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "unknown" || r.Status != 0 || r.FinishedAt != nil {
		t.Fatalf("fabricated crash result: %+v", r)
	}
}

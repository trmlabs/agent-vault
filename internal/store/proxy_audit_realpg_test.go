//go:build realpg

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestRealPostgres_ProxyAuditPersistenceAndUnknownOutcome(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL to a disposable PostgreSQL database")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	ctx := context.Background()
	prefix := fmt.Sprintf("audit-test-%d-", time.Now().UnixNano())
	ids := []string{prefix + "pending", prefix + "completed", prefix + "denied", prefix + "recovered"}
	defer func() {
		for _, id := range ids {
			s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM credential_proxy_audit WHERE request_id=?`), id)
		}
	}()
	// Verify the writer forces a synchronous commit even if the connection's
	// session default explicitly permits asynchronous durability.
	s.db.SetMaxOpenConns(1)
	if _, err := s.db.ExecContext(ctx, `SET synchronous_commit = off`); err != nil {
		t.Fatal(err)
	}
	if err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		var mode string
		if err := tx.QueryRowContext(ctx, `SHOW synchronous_commit`).Scan(&mode); err != nil {
			return err
		}
		if mode != "on" {
			return fmt.Errorf("audit transaction has asynchronous commit mode")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids[:3] {
		decision := "allow"
		if i == 2 {
			decision = "deny"
		}
		if err := s.InsertProxyAudit(ctx, ProxyAudit{RequestID: id, VaultID: "fixture-vault", ActorType: "workload", ActorID: "fixture-actor", WorkloadID: "fixture-pod", Destination: "api.example.test", Service: "fixture-service", MappingIDs: []string{"fixture-mapping"}, Method: "GET", Decision: decision}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CompleteProxyAudit(ctx, ids[1], "completed", 200); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, ids[2], "denied", 403); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, prefix+"missing", "completed", 200); err == nil {
		t.Fatal("nonexistent audit attempt completed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, ids[0], "completed", 200); err == nil {
		t.Fatal("unavailable outcome store acknowledged completion")
	}
	reopened, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	s = reopened
	for i, id := range ids[:3] {
		row, err := s.GetProxyAudit(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"unknown", "completed", "denied"}[i]
		if row.Outcome != want || row.StartedAt.IsZero() || row.ActorID != "fixture-actor" || row.WorkloadID != "fixture-pod" || len(row.MappingIDs) != 1 || row.MappingIDs[0] != "fixture-mapping" {
			t.Fatalf("audit row failed to survive reconnection: outcome %s", row.Outcome)
		}
		if i == 0 && (row.Status != 0 || row.FinishedAt != nil) {
			t.Fatal("failed completion fabricated a final outcome")
		}
		if i > 0 && (row.FinishedAt == nil || row.Status != []int{0, 200, 403}[i]) {
			t.Fatal("completed outcome lost its status or timestamp")
		}
	}
	if err := s.CompleteProxyAudit(ctx, ids[1], "upstream_error", 502); err == nil {
		t.Fatal("completed audit outcome overwritten")
	}
	if err := s.InsertProxyAudit(ctx, ProxyAudit{RequestID: ids[3], Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteProxyAudit(ctx, ids[3], "completed", 204); err != nil {
		t.Fatal("audit did not resume after storage recovery")
	}
}

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func checkDatabaseCleanupJournal(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-a", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.ReleaseDatabaseCleanupOwner(ctx, "owner-a")
		_ = s.ReleaseDatabaseCleanupOwner(ctx, "owner-b")
	})
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-b", now, now.Add(time.Minute)); err == nil {
		t.Fatal("second broker acquired live owner")
	}
	record := DatabaseCleanup{Accessor: "test-accessor", Binding: "test-binding"}
	if err := s.AddDatabaseCleanup(ctx, "owner-b", record); err == nil {
		t.Fatal("non-owner journal write accepted")
	}
	if err := s.AddDatabaseCleanup(ctx, "owner-a", record); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(rows) != 1 || rows[0] != record {
		t.Fatalf("journal roundtrip: rows=%d err=%v", len(rows), err)
	}
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "owner-a"); err != nil {
		t.Fatal(err)
	}
	// A released owner cannot renew itself into authority or erase its successor.
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-b", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "owner-a", now, now.Add(time.Minute)); err == nil {
		t.Fatal("stale owner renewed")
	}
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "owner-b", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDatabaseCleanup(ctx, record.Accessor); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDatabaseCleanup(ctx, record.Accessor); err != nil {
		t.Fatal("delete not idempotent", err)
	}
}

func TestDatabaseCleanupJournalOwnership(t *testing.T) { checkDatabaseCleanupJournal(t, openTestDB(t)) }

func TestDatabaseCleanupOperatorConfirmationIsExactAndRetained(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"unknown-one", "unknown-two", "known"} {
		if err := s.AddDatabaseCleanup(ctx, "owner", DatabaseCleanup{Accessor: id, Binding: "vault/db"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetDatabaseCleanupLease(ctx, "owner", "known", "database/creds/reader/lease"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ id, evidence string }{{"missing", "verified"}, {"known", "verified"}, {"unknown-one", ""}} {
		if err := s.ConfirmDatabaseCleanup(ctx, "owner", test.id, test.evidence); err == nil {
			t.Fatalf("invalid confirmation accepted for %s", test.id)
		}
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "other-owner", "unknown-one", "verified"); err == nil {
		t.Fatal("stale owner confirmed recovery")
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "owner", "unknown-one", "operator and database evidence"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "owner", "unknown-one", "replace evidence"); err == nil {
		t.Fatal("original assertion overwritten")
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("confirmation changed other records: %v", err)
	}
	var evidence string
	if err := s.db.QueryRowContext(ctx, "SELECT reconciliation_evidence FROM database_cleanup WHERE accessor = 'unknown-one'").Scan(&evidence); err != nil || evidence != "operator and database evidence" {
		t.Fatal("confirmation evidence not retained", err)
	}
}

func TestDatabaseCleanupJournalSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	if err = s.ClaimDatabaseCleanupOwner(ctx, "old", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.AddDatabaseCleanup(ctx, "old", DatabaseCleanup{Accessor: "accessor", Binding: "binding"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	records, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("lost durable record: %v", err)
	}
	if err = s.ClaimDatabaseCleanupOwner(ctx, "new", now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.RenewDatabaseCleanupOwner(ctx, "old", now.Add(2*time.Minute), now.Add(3*time.Minute)); err == nil {
		t.Fatal("expired owner renewed")
	}
}

// Confirmation must not let a subsequently delivered issuance response hide a
// real lease behind retained reconciliation evidence. The minter treats a
// rejected lease update as a cleanup-required admission failure.
func TestDatabaseCleanupRejectsLeaseAfterOperatorConfirmation(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDatabaseCleanup(ctx, "owner", DatabaseCleanup{Accessor: "pending", Binding: "vault/db"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "owner", "pending", "verified absence before late response"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDatabaseCleanupLease(ctx, "owner", "pending", "database/creds/reader/late"); err == nil {
		t.Fatal("late lease persistence succeeded on a reconciled row")
	}
}

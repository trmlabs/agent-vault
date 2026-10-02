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

func TestCheckDatabaseCleanupOwnerDoesNotExtendClaim(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "observe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "observer-test", now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "observer-test", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "other", now); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "observer-test", now.Add(2*time.Second)); err == nil {
		t.Fatal("observation extended ownership")
	}
}

func TestDatabaseCleanupRecordsActor(t *testing.T) { checkDatabaseCleanupRecordsActor(t, openTestDB(t)) }

func checkDatabaseCleanupRecordsActor(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.DeleteDatabaseCleanup(ctx, "actor-a")
		_ = s.DeleteDatabaseCleanup(ctx, "actor-b")
		_ = s.ReleaseDatabaseCleanupOwner(ctx, "owner")
	})
	for _, record := range []DatabaseCleanup{{Accessor: "actor-a", Binding: "vault/db", ActorID: "agent-one"}, {Accessor: "actor-b", Binding: "vault/db"}} {
		if err := s.AddDatabaseCleanup(ctx, "owner", record); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(rows) != 2 || rows[0].ActorID != "agent-one" || rows[1].ActorID != "" {
		t.Fatalf("actor attribution not retained: %+v %v", rows, err)
	}
}

// The live SQLite store predates actor attribution. Its pending records must
// survive the upgrade unchanged and read back as unattributed.
func TestDatabaseCleanupActorMigrationKeepsLegacyRecordsUnattributed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	checkDatabaseCleanupActorMigration(t, func() (*SQLStore, error) { return Open(path) })
}

// checkDatabaseCleanupActorMigration rewinds the journal to its pre-attribution
// shape with pending records, then proves reopening upgrades it exactly once.
func checkDatabaseCleanupActorMigration(t *testing.T, open func() (*SQLStore, error)) {
	t.Helper()
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DROP TABLE database_cleanup`,
		`CREATE TABLE database_cleanup (accessor TEXT PRIMARY KEY, binding TEXT NOT NULL,
			lease_id TEXT NOT NULL DEFAULT '', reconciliation_evidence TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO database_cleanup (accessor, binding, lease_id) VALUES ('legacy-known', 'vault/db', 'database/creds/reader/one'), ('legacy-unknown', 'vault/db', '')`,
		`DELETE FROM schema_migrations WHERE name = '20261001120000_database_cleanup_actor'`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 { // The second open proves the migration is recorded once.
		s, err = open()
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListDatabaseCleanup(context.Background())
		if err != nil || len(rows) != 2 {
			t.Fatalf("legacy records lost: %d %v", len(rows), err)
		}
		if rows[0] != (DatabaseCleanup{Accessor: "legacy-known", Binding: "vault/db", LeaseID: "database/creds/reader/one"}) ||
			rows[1] != (DatabaseCleanup{Accessor: "legacy-unknown", Binding: "vault/db"}) {
			t.Fatalf("legacy records changed: %+v", rows)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	s, err = open()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, accessor := range []string{"legacy-known", "legacy-unknown"} {
		if err := s.DeleteDatabaseCleanup(context.Background(), accessor); err != nil {
			t.Fatal(err)
		}
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetFleetTables empties the fleet tables, so a reused PostgreSQL test
// database starts clean.
func resetFleetTables(t *testing.T, s *SQLStore) {
	t.Helper()
	for _, table := range []string{"database_cleanup", "database_cleanup_replica", "broker_sessions"} {
		if _, err := s.db.Exec("DELETE FROM " + table); err != nil { // #nosec G202 -- fixed table names
			t.Fatal(err)
		}
	}
}

func checkDatabaseCleanupJournal(t *testing.T, s *SQLStore) {
	t.Helper()
	resetFleetTables(t, s)
	t.Cleanup(func() { resetFleetTables(t, s) })
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	// Replicas coexist; each owns only what it wrote.
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-b", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-a", time.Minute); err == nil {
		t.Fatal("owner registered twice")
	}
	record := DatabaseCleanup{Accessor: "test-accessor", Binding: "test-binding"}
	if err := s.AddDatabaseCleanup(ctx, "owner-unregistered", record); err == nil {
		t.Fatal("unregistered owner journal write accepted")
	}
	if err := s.AddDatabaseCleanup(ctx, "owner-a", record); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDatabaseCleanupLease(ctx, "owner-b", record.Accessor, "database/creds/r/x"); err == nil {
		t.Fatal("another replica set this replica's lease")
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(rows) != 1 || rows[0] != record {
		t.Fatalf("journal roundtrip: rows=%d err=%v", len(rows), err)
	}
	if owned, err := s.ListOwnedDatabaseCleanup(ctx, "owner-b"); err != nil || len(owned) != 0 {
		t.Fatalf("live replica's record listed for another: %d %v", len(owned), err)
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "owner-b"); err != nil || n != 0 {
		t.Fatalf("live replica's record claimed: %d %v", n, err)
	}
	if live, err := s.LiveDatabaseCleanupOwners(ctx); err != nil || live != 2 {
		t.Fatalf("live owners = %d, %v", live, err)
	}
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "owner-a"); err != nil {
		t.Fatal(err)
	}
	// A released owner cannot renew itself into authority; its records move.
	if err := s.RenewDatabaseCleanupOwner(ctx, "owner-a", time.Minute); !errors.Is(err, ErrDatabaseCleanupOwnershipLost) {
		t.Fatalf("released owner renewed: %v", err)
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "owner-b"); err != nil || n != 1 {
		t.Fatalf("orphan not claimed: %d %v", n, err)
	}
	if owned, err := s.ListOwnedDatabaseCleanup(ctx, "owner-b"); err != nil || len(owned) != 1 {
		t.Fatalf("claimed record not owned: %d %v", len(owned), err)
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "owner-b"); err != nil || n != 0 {
		t.Fatalf("claim not idempotent: %d %v", n, err)
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "owner-b", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDatabaseCleanup(ctx, record.Accessor); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDatabaseCleanup(ctx, record.Accessor); err != nil {
		t.Fatal("delete not idempotent", err)
	}
	checkOwnerExpiresByDatabaseClock(t, s)
	checkSurvivorsRaceToClaim(t, s)
	checkPodSessionCap(t, s)
}

// Expiry is decided by the database clock. The API takes no replica time, and
// an expired owner never comes back.
func checkOwnerExpiresByDatabaseClock(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "short", 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDatabaseCleanup(ctx, "short", DatabaseCleanup{Accessor: "short-accessor", Binding: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "short"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if err := s.CheckDatabaseCleanupOwner(ctx, "short"); !errors.Is(err, ErrDatabaseCleanupOwnershipLost) {
		t.Fatalf("expired owner still live: %v", err)
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "short", time.Minute); !errors.Is(err, ErrDatabaseCleanupOwnershipLost) {
		t.Fatalf("expired owner revived: %v", err)
	}
	if err := s.AddDatabaseCleanup(ctx, "short", DatabaseCleanup{Accessor: "late", Binding: "b"}); err == nil {
		t.Fatal("expired owner wrote a record")
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "owner-b"); err != nil || n != 1 {
		t.Fatalf("expired owner's record not claimed: %d %v", n, err)
	}
	if err := s.DeleteDatabaseCleanup(ctx, "short-accessor"); err != nil {
		t.Fatal(err)
	}
}

// Two survivors claim a dead replica's records at the same moment. Each record
// moves exactly once: the claimed counts add up to the record count.
func checkSurvivorsRaceToClaim(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	const records = 200
	if err := s.ClaimDatabaseCleanupOwner(ctx, "dead", time.Minute); err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if err := s.AddDatabaseCleanup(ctx, "dead", DatabaseCleanup{Accessor: fmt.Sprintf("race-%03d", i), Binding: "b"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, owner := range []string{"survivor-1", "survivor-2"} {
		if err := s.ClaimDatabaseCleanupOwner(ctx, owner, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "dead"); err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		var wg sync.WaitGroup
		claimed := make([]int, 2)
		start := make(chan struct{})
		for i, owner := range []string{"survivor-1", "survivor-2"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for {
					n, err := s.ClaimOrphanedDatabaseCleanup(ctx, owner)
					if err == nil {
						claimed[i] = n
						return
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		one, _ := s.ListOwnedDatabaseCleanup(ctx, "survivor-1")
		two, _ := s.ListOwnedDatabaseCleanup(ctx, "survivor-2")
		if claimed[0]+claimed[1] != records || len(one)+len(two) != records || len(one) != claimed[0] {
			t.Fatalf("round %d: claimed %v, owned %d+%d of %d", round, claimed, len(one), len(two), records)
		}
		// Hand everything back to a dead owner for the next round.
		if _, err := s.db.Exec("UPDATE database_cleanup SET owner = 'dead' WHERE accessor LIKE 'race-%'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("DELETE FROM database_cleanup WHERE accessor LIKE 'race-%'"); err != nil {
		t.Fatal(err)
	}
}

func checkPodSessionCap(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	const limit, attempts = 5, 20
	// survivor-2 holds one session for certain, so its release below always
	// lowers the count, however the race spreads the rest.
	if err := s.AddBrokerSession(ctx, "survivor-2", "session-first", "pod-uid-1", limit); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted, refused := 0, 0
	byOwner := map[string]int{"survivor-2": 1}
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := []string{"survivor-1", "survivor-2"}[i%2]
			for {
				err := s.AddBrokerSession(ctx, owner, fmt.Sprintf("session-%d", i), "pod-uid-1", limit)
				mu.Lock()
				switch {
				case err == nil:
					admitted++
					byOwner[owner]++
				case errors.Is(err, ErrPodSessionLimit):
					refused++
				default:
					mu.Unlock()
					continue // SQLite busy; retry
				}
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()
	if admitted != limit-1 || refused != attempts-limit+1 {
		t.Fatalf("admitted %d refused %d, want %d and %d", admitted, refused, limit-1, attempts-limit+1)
	}
	if n, err := s.CountPodSessions(ctx, "pod-uid-1"); err != nil || n != limit {
		t.Fatalf("count = %d, %v", n, err)
	}
	// A dead replica's sessions stop counting at once and are swept later.
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "survivor-2"); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountPodSessions(ctx, "pod-uid-1")
	if err != nil || n != limit-byOwner["survivor-2"] {
		t.Fatalf("dead replica's sessions still count: %d, want %d, %v", n, limit-byOwner["survivor-2"], err)
	}
	if _, err := s.ClaimOrphanedDatabaseCleanup(ctx, "survivor-1"); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM broker_sessions").Scan(&rows); err != nil || rows != n {
		t.Fatalf("dead replica's session rows not swept: %d of %d, %v", rows, n, err)
	}
	if err := s.AddBrokerSession(ctx, "survivor-2", "session-dead", "pod-uid-1", 0); err == nil {
		t.Fatal("dead replica recorded a session")
	}
	if err := s.RemoveBrokerSession(ctx, "session-0"); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseCleanupJournalOwnership(t *testing.T) { checkDatabaseCleanupJournal(t, openTestDB(t)) }

func TestDatabaseCleanupOperatorConfirmationIsExactAndRetained(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", time.Minute); err != nil {
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

// An unknown issuance quarantines its binding for every replica, not only for
// the owner that found it.
func TestDatabaseCleanupQuarantineIsFleetWide(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	for _, owner := range []string{"owner", "other"} {
		if err := s.ClaimDatabaseCleanupOwner(ctx, owner, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddDatabaseCleanup(ctx, "owner", DatabaseCleanup{Accessor: "unknown", Binding: "vault/db"}); err != nil {
		t.Fatal(err)
	}
	// In flight: not yet quarantined, so other replicas keep minting.
	if q, err := s.DatabaseBindingQuarantined(ctx, "vault/db"); err != nil || q {
		t.Fatalf("in-flight issuance quarantined: %v %v", q, err)
	}
	if err := s.QuarantineDatabaseCleanup(ctx, "other", "unknown"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.DatabaseBindingQuarantined(ctx, "vault/db"); q {
		t.Fatal("non-owner quarantined a record")
	}
	if err := s.QuarantineDatabaseCleanup(ctx, "owner", "unknown"); err != nil {
		t.Fatal(err)
	}
	if q, err := s.DatabaseBindingQuarantined(ctx, "vault/db"); err != nil || !q {
		t.Fatalf("quarantine not visible fleet-wide: %v %v", q, err)
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "other", "unknown", "operator verified no role remains"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.DatabaseBindingQuarantined(ctx, "vault/db"); q {
		t.Fatal("confirmation did not lift quarantine")
	}
}

func TestDatabaseCleanupJournalSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = s.ClaimDatabaseCleanupOwner(ctx, "old", time.Minute); err != nil {
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
	// A restarted process is a new owner. It waits for the old row to expire.
	if err = s.ClaimDatabaseCleanupOwner(ctx, "new", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "new"); err != nil || n != 0 {
		t.Fatalf("live owner's record taken early: %d %v", n, err)
	}
}

// The fleet migration runs on an existing SQLite store with live records from
// the single-owner schema. Records survive, have no owner, and the first live
// broker claims them.
func TestDatabaseCleanupFleetMigrationKeepsLiveRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"DROP TABLE database_cleanup_replica",
		"DROP TABLE broker_sessions",
		"DROP TABLE database_cleanup",
		`CREATE TABLE database_cleanup (accessor TEXT PRIMARY KEY, binding TEXT NOT NULL,
			lease_id TEXT NOT NULL DEFAULT '', reconciliation_evidence TEXT NOT NULL DEFAULT '')`,
		"INSERT INTO database_cleanup (accessor, binding, lease_id) VALUES ('legacy-known', 'vault/db', 'database/creds/r/1'), ('legacy-unknown', 'vault/db', '')",
		"INSERT INTO database_cleanup_owner (id, owner, expires_ns) VALUES (1, 'old-binary', 0)",
		"DELETE FROM schema_migrations WHERE name IN ('20261001120000_database_cleanup_actor', '20261001130000_database_cleanup_workload', '20261003120000_database_cleanup_fleet', '20261009120000_database_cleanup_issuance')",
	} {
		if _, err := s.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = Open(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	records, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 2 {
		t.Fatalf("migration lost records: %d %v", len(records), err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "first", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ClaimOrphanedDatabaseCleanup(ctx, "first"); err != nil || n != 2 {
		t.Fatalf("legacy records not claimed: %d %v", n, err)
	}
}

// Confirmation must not let a subsequently delivered issuance response hide a
// real lease behind retained reconciliation evidence. The minter treats a
// rejected lease update as a cleanup-required admission failure.
func TestDatabaseCleanupRejectsLeaseAfterOperatorConfirmation(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", time.Minute); err != nil {
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
	s := openTestDB(t)
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "observer-test", 400*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "other"); err == nil {
		t.Fatal("wrong owner accepted")
	}
	for range 3 {
		if err := s.CheckDatabaseCleanupOwner(ctx, "observer-test"); err != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := s.CheckDatabaseCleanupOwner(ctx, "observer-test"); err == nil {
		t.Fatal("observation extended ownership")
	}
}

func TestDatabaseCleanupRecordsActor(t *testing.T) {
	checkDatabaseCleanupRecordsActor(t, openTestDB(t))
}

func checkDatabaseCleanupRecordsActor(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner", time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.DeleteDatabaseCleanup(ctx, "actor-a")
		_ = s.DeleteDatabaseCleanup(ctx, "actor-b")
		_ = s.ReleaseDatabaseCleanupOwner(ctx, "owner")
	})
	for _, record := range []DatabaseCleanup{{Accessor: "actor-a", Binding: "vault/db", ActorID: "agent-one", WorkloadID: "pod-uid-one"}, {Accessor: "actor-b", Binding: "vault/db"}} {
		if err := s.AddDatabaseCleanup(ctx, "owner", record); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil || len(rows) != 2 || rows[0].ActorID != "agent-one" || rows[0].WorkloadID != "pod-uid-one" || rows[1].ActorID != "" || rows[1].WorkloadID != "" {
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
		`DELETE FROM schema_migrations WHERE name IN ('20261001120000_database_cleanup_actor', '20261001130000_database_cleanup_workload',
			'20261003120000_database_cleanup_fleet', '20261009120000_database_cleanup_issuance')`,
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

// One replica name, two live processes: the second is refused, and if a race
// ever registered both, neither renews (both fence).
func TestDatabaseCleanupReplicaNameIsExclusive(t *testing.T) {
	checkReplicaNameExclusive(t, openTestDB(t))
}

func checkReplicaNameExclusive(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "broker-0/aaaa", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "broker-0/bbbb", time.Minute); !errors.Is(err, ErrReplicaNameInUse) {
		t.Fatalf("second boot under the same name: %v, want ErrReplicaNameInUse", err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "broker-1/cccc", time.Minute); err != nil {
		t.Fatalf("another replica name refused: %v", err)
	}
	// Owners without a replica name are not grouped.
	if err := s.ClaimDatabaseCleanupOwner(ctx, "dddd", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "eeee", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "broker-0/aaaa", time.Minute); err != nil {
		t.Fatalf("sole holder could not renew: %v", err)
	}
	// Simulate a racing claim that slipped past the check.
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup_replica (owner, expires_ms) VALUES (?, `+s.dbNowMs()+` + 60000)`), "broker-0/ffff"); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"broker-0/aaaa", "broker-0/ffff"} {
		if err := s.RenewDatabaseCleanupOwner(ctx, owner, time.Minute); !errors.Is(err, ErrReplicaNameInUse) {
			t.Fatalf("%s renewed beside a duplicate: %v", owner, err)
		}
	}
	if err := s.RenewDatabaseCleanupOwner(ctx, "broker-1/cccc", time.Minute); err != nil {
		t.Fatalf("an unrelated replica stopped renewing: %v", err)
	}
	// Once the other boot is gone, the name is free again.
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "broker-0/ffff"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseDatabaseCleanupOwner(ctx, "broker-0/aaaa"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "broker-0/gggg", time.Minute); err != nil {
		t.Fatalf("name not reusable after release: %v", err)
	}
}

// Boots that start at the same moment under one replica name: exactly one
// registers, however the claims interleave.
func checkConcurrentReplicaClaims(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	replica := "race-" + time.Now().Format("150405.000000000")
	const boots = 16
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := range boots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.ClaimDatabaseCleanupOwner(ctx, fmt.Sprintf("%s/boot-%02d", replica, i), time.Minute) == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	t.Cleanup(func() {
		for i := range boots {
			_ = s.ReleaseDatabaseCleanupOwner(ctx, fmt.Sprintf("%s/boot-%02d", replica, i))
		}
	})
	if n := won.Load(); n != 1 {
		t.Fatalf("%d concurrent boots registered one replica name, want 1", n)
	}
}

func TestConcurrentReplicaClaims(t *testing.T) { checkConcurrentReplicaClaims(t, openTestDB(t)) }

func TestDatabaseCleanupSettledUnknownIssuance(t *testing.T) {
	checkSettledUnknownIssuance(t, openTestDB(t))
}

// checkSettledUnknownIssuance: an unknown issuance qualifies for the automatic
// check only once its child token has been dead for the settle time, by
// revocation or expiry, and only when it names its credential path.
func checkSettledUnknownIssuance(t *testing.T, s *SQLStore) {
	t.Helper()
	resetFleetTables(t, s)
	t.Cleanup(func() { resetFleetTables(t, s) })
	ctx := context.Background()
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimDatabaseCleanupOwner(ctx, "owner-b", time.Minute); err != nil {
		t.Fatal(err)
	}
	add := func(accessor, mount, role string, ttl time.Duration) {
		t.Helper()
		record := DatabaseCleanup{Accessor: accessor, Binding: "vault/db", Mount: mount, Role: role, TokenTTL: ttl}
		if err := s.AddDatabaseCleanup(ctx, "owner-a", record); err != nil {
			t.Fatal(err)
		}
	}
	add("expiring", "database", "reader", 300*time.Millisecond)
	add("revoked", "database", "reader", time.Hour)
	add("held", "database", "reader", time.Hour)
	add("legacy", "", "", 300*time.Millisecond)
	add("known", "database", "reader", 300*time.Millisecond)
	if err := s.SetDatabaseCleanupLease(ctx, "owner-a", "known", "database/creds/reader/1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDatabaseCleanupTokenRevoked(ctx, "owner-b", "revoked"); err == nil {
		t.Fatal("another replica marked this replica's token revoked")
	}
	if err := s.MarkDatabaseCleanupTokenRevoked(ctx, "owner-a", "revoked"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDatabaseCleanupTokenRevoked(ctx, "owner-a", "known"); err == nil {
		t.Fatal("a known lease's token was marked as an unknown issuance's")
	}
	settled := func(owner string, settle time.Duration) []string {
		t.Helper()
		rows, err := s.SettledDatabaseCleanup(ctx, owner, settle)
		if err != nil {
			t.Fatal(err)
		}
		var accessors []string
		for _, row := range rows {
			accessors = append(accessors, row.Accessor)
		}
		return accessors
	}
	if got := settled("owner-a", time.Minute); len(got) != 0 {
		t.Fatalf("settled before the settle time: %v", got)
	}
	if got := settled("owner-a", 0); fmt.Sprint(got) != "[revoked]" {
		t.Fatalf("settled at once %v, want only the revoked token", got)
	}
	if got := settled("owner-b", 0); len(got) != 0 {
		t.Fatalf("another owner's records settled: %v", got)
	}
	time.Sleep(400 * time.Millisecond)
	if got := settled("owner-a", 50*time.Millisecond); fmt.Sprint(got) != "[expiring revoked]" {
		t.Fatalf("settled after expiry %v, want the expired and revoked tokens", got)
	}
	rows, err := s.ListDatabaseCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Accessor == "expiring" && (row.Mount != "database" || row.Role != "reader") {
			t.Fatalf("credential path not kept: %+v", row)
		}
	}
	if err := s.ConfirmDatabaseCleanup(ctx, "owner-a", "revoked", "automated"); err != nil {
		t.Fatal(err)
	}
	if got := settled("owner-a", 50*time.Millisecond); fmt.Sprint(got) != "[expiring]" {
		t.Fatalf("a confirmed record still settled: %v", got)
	}
}

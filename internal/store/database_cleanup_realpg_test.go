//go:build realpg

package store

import (
	"os"
	"testing"
)

func TestRealPostgres_DatabaseCleanupJournal(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) // after the journal's own cleanup
	checkDatabaseCleanupJournal(t, s)
}

func TestRealPostgres_DatabaseCleanupActor(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	checkDatabaseCleanupActorMigration(t, func() (*SQLStore, error) { return openPostgres(dsn) })
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Close after the checks' own cleanups release their owner claims.
	t.Cleanup(func() { _ = s.Close() })
	checkDatabaseCleanupRecordsActor(t, s)
}

func TestRealPostgres_DatabaseCleanupReplicaNameIsExclusive(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	checkReplicaNameExclusive(t, s)
}

func TestRealPostgres_RunnerSessionPins(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	checkRunnerSessionPins(t, s)
}

func TestRealPostgres_ConcurrentReplicaClaims(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	checkConcurrentReplicaClaims(t, s)
}

func TestRealPostgres_DatabaseCleanupSettledUnknownIssuance(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	checkSettledUnknownIssuance(t, s)
}

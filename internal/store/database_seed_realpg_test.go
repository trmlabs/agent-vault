//go:build realpg

package store

import (
	"os"
	"testing"
)

func TestRealPostgres_DatabaseSeedHistory(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkDatabaseSeedHistory(t, s)
}

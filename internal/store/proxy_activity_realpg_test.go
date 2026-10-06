//go:build realpg

package store

import (
	"os"
	"testing"
)

func TestRealPostgres_ProxyActivity(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL to a disposable PostgreSQL database")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	checkProxyActivity(t, s)
	checkProxyActivityHistoryAndCeiling(t, s)
	checkProxyActivitySequence(t, s)
	checkProxyActivityStreamCeiling(t, s)
}

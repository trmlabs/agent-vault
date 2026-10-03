//go:build realpg

package pgproxy

import (
	"os"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

// The target deployment keeps the cleanup journal on PostgreSQL.
func TestRealPostgresStore_CleanupSnapshotPartitionsByActor(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	opened, err := store.OpenStore(store.StoreConfig{DatabaseURL: dsn})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := opened.(*store.SQLStore)
	if !ok {
		t.Fatalf("unexpected store type %T", opened)
	}
	t.Cleanup(func() { _ = st.Close() })
	client, _, _ := durableFixtureOn(t, st)
	checkCleanupSnapshotPartition(t, client, st)
}

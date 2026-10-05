//go:build realpg

package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// migrate-db carries the broker's tables to PostgreSQL. A pending cleanup
// record arrives without an owner, so the first live broker claims it, and the
// audit boot counter continues instead of restarting at 1.
func TestRealPostgres_MigrateCarriesBrokerTables(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	ctx := context.Background()
	admin, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("migrate_%d", time.Now().UnixNano())
	if _, err := admin.db.Exec("CREATE DATABASE " + name); err != nil { // #nosec G202 -- generated name
		t.Fatal(err)
	}
	defer func() { _, _ = admin.db.Exec("DROP DATABASE " + name + " WITH (FORCE)") }() // #nosec G202 -- generated name
	target, _ := url.Parse(dsn)
	target.Path = "/" + name

	src, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := src.ClaimDatabaseCleanupOwner(ctx, "sqlite-broker", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := src.AddDatabaseCleanup(ctx, "sqlite-broker", DatabaseCleanup{Accessor: "pending", Binding: "vault/db"}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetDatabaseCleanupLease(ctx, "sqlite-broker", "pending", "database/creds/readonly/abc"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, _, err := src.BeginAuditBoot(ctx, "broker-0"); err != nil {
			t.Fatal(err)
		}
	}
	if err := src.InsertProxyAudit(ctx, ProxyAudit{RequestID: "r1", VaultID: "v", ActorType: "agent", ActorID: "a", WorkloadID: "w",
		Destination: "api.example.test", Service: "s", Method: "GET", Decision: "allow", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	dst, err := openPostgres(target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := MigrateData(ctx, src, dst, nil); err != nil {
		t.Fatal(err)
	}
	records, err := dst.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 1 || records[0].LeaseID != "database/creds/readonly/abc" {
		t.Fatalf("pending cleanup not carried: %+v %v", records, err)
	}
	if err := dst.ClaimDatabaseCleanupOwner(ctx, "fleet-0", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := dst.ClaimOrphanedDatabaseCleanup(ctx, "fleet-0"); err != nil || n != 1 {
		t.Fatalf("migrated record not claimable: %d %v", n, err)
	}
	boot, _, err := dst.BeginAuditBoot(ctx, "broker-0")
	if err != nil || boot != 4 {
		t.Fatalf("audit boot after migration = %d, want 4: %v", boot, err)
	}
	var audits int
	if err := dst.db.QueryRow("SELECT COUNT(*) FROM credential_proxy_audit").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("proxy audit not carried: %d %v", audits, err)
	}
}

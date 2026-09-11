//go:build realpg

package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestRealPostgres_DatabaseServiceLifecycle(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL to a disposable PostgreSQL database")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	v, err := s.CreateVault(ctx, fmt.Sprintf("db-review-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DeleteVault(ctx, v.Name)
	svc, err := s.UpsertDatabaseService(ctx, DatabaseService{VaultID: v.ID, Name: "analytics", Upstream: "db:5432", Mount: "database", Role: "readonly", MaxConns: 3})
	if err != nil {
		t.Fatal(err)
	}
	if svc.SSLMode != "prefer" || svc.CreatedAt.IsZero() {
		t.Fatal("defaults or timestamps did not round-trip")
	}
	id := svc.ID
	svc.MaxConns = 1
	svc, err = s.UpsertDatabaseService(ctx, *svc)
	if err != nil || svc.ID != id {
		t.Fatalf("upsert: %v", err)
	}
	if limit, err := s.DatabaseUpstreamLimit(ctx, "db:5432"); err != nil || limit != 1 {
		t.Fatalf("limit %d: %v", limit, err)
	}
	if err := s.DeleteVault(ctx, v.Name); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.ListDatabaseServices(ctx, v.ID); err != nil || len(rows) != 0 {
		t.Fatalf("cascade failed: %v", err)
	}
	// Migration history must also reopen cleanly on an existing database.
	reopened, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

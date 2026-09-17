package server

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestDatabaseSeedDeletionSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "seed.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := st.CreateVault(ctx, "seed-test")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string][]pgproxy.DatabaseService{"seed-test": {{Name: "analytics", Addr: "localhost:5432", Database: "app", Mount: "database", Role: "readonly", SSLMode: "require"}}}
	srv := newTestServer(withStore(st))
	if n, err := srv.SeedDatabaseServices(ctx, config); err != nil || n != 1 {
		t.Fatalf("bootstrap: count=%d err=%v", n, err)
	}
	original, err := st.GetDatabaseService(ctx, vault.ID, "analytics")
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := st.DeleteDatabaseService(ctx, vault.ID, "analytics"); err != nil || !removed {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv = newTestServer(withStore(st))
	if n, err := srv.SeedDatabaseServices(ctx, config); err != nil || n != 0 {
		t.Fatalf("restart resurrected deleted binding: count=%d err=%v", n, err)
	}
	if _, err := st.GetDatabaseService(ctx, vault.ID, "analytics"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted binding accessible: %v", err)
	}
	original.Role = "explicit-readd"
	if _, err := st.UpsertDatabaseService(ctx, *original); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.SeedDatabaseServices(ctx, config); err != nil || n != 0 {
		t.Fatalf("reseed after explicit add: count=%d err=%v", n, err)
	}
	got, err := st.GetDatabaseService(ctx, vault.ID, "analytics")
	if err != nil || got.Role != "explicit-readd" {
		t.Fatalf("explicit add overwritten: %+v err=%v", got, err)
	}
}

package store

import (
	"context"
	"database/sql"
	"testing"
)

func sampleService(vaultID, name string) DatabaseService {
	return DatabaseService{
		VaultID:  vaultID,
		Name:     name,
		Upstream: "db.internal:5432",
		Database: "appdb",
		Mount:    "database",
		Role:     "ro",
		SSLMode:  "require",
		MaxConns: 10,
	}
}

func TestDatabaseServiceCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.CreateVault(ctx, "db-svc-test")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// A fresh vault has no services.
	list, err := s.ListDatabaseServices(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListDatabaseServices: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no services, got %d", len(list))
	}

	// Get on a missing service reports not-found.
	if _, err := s.GetDatabaseService(ctx, ns.ID, "nope"); err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}

	// Upsert creates the row and returns it fully populated.
	created, err := s.UpsertDatabaseService(ctx, sampleService(ns.ID, "alloy"))
	if err != nil {
		t.Fatalf("UpsertDatabaseService: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected a generated ID")
	}
	if created.Upstream != "db.internal:5432" || created.Role != "ro" || created.SSLMode != "require" || created.MaxConns != 10 {
		t.Fatalf("round-trip mismatch: %+v", created)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps set: %+v", created)
	}

	// Get returns the same row.
	got, err := s.GetDatabaseService(ctx, ns.ID, "alloy")
	if err != nil {
		t.Fatalf("GetDatabaseService: %v", err)
	}
	if got.ID != created.ID || got.Database != "appdb" {
		t.Fatalf("get mismatch: %+v", got)
	}
}

// TestDatabaseServiceEmptySSLModeNormalizes pins that an empty sslmode is stored
// as "prefer" rather than tripping the column's CHECK constraint.
func TestDatabaseServiceEmptySSLModeNormalizes(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "db-sslmode")

	svc := sampleService(ns.ID, "nossl")
	svc.SSLMode = ""
	created, err := s.UpsertDatabaseService(ctx, svc)
	if err != nil {
		t.Fatalf("upsert with empty sslmode: %v", err)
	}
	if created.SSLMode != "prefer" {
		t.Fatalf("expected normalized sslmode 'prefer', got %q", created.SSLMode)
	}
	got, _ := s.GetDatabaseService(ctx, ns.ID, "nossl")
	if got.SSLMode != "prefer" {
		t.Fatalf("stored sslmode should be 'prefer', got %q", got.SSLMode)
	}
}

func TestDatabaseServiceUpsertIsIdempotentByName(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "db-upsert")

	first, err := s.UpsertDatabaseService(ctx, sampleService(ns.ID, "crunchy"))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Re-upsert the same name with changed coordinates: same row (id + created_at
	// preserved), fields overwritten in place, not a duplicate.
	changed := sampleService(ns.ID, "crunchy")
	changed.Upstream = "crunchy.internal:5433"
	changed.Role = "rw"
	changed.MaxConns = 25
	second, err := s.UpsertDatabaseService(ctx, changed)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected same id on re-upsert, got %s vs %s", second.ID, first.ID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("expected created_at preserved, got %v vs %v", second.CreatedAt, first.CreatedAt)
	}
	if second.Upstream != "crunchy.internal:5433" || second.Role != "rw" || second.MaxConns != 25 {
		t.Fatalf("expected fields overwritten, got %+v", second)
	}

	list, _ := s.ListDatabaseServices(ctx, ns.ID)
	if len(list) != 1 {
		t.Fatalf("expected exactly one row after re-upsert, got %d", len(list))
	}
}

func TestDatabaseServiceListOrderedAndScopedByVault(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	v1, _ := s.CreateVault(ctx, "vault-one")
	v2, _ := s.CreateVault(ctx, "vault-two")

	// Insert out of order in v1; v2 gets its own service.
	for _, name := range []string{"zeta", "alpha", "mu"} {
		if _, err := s.UpsertDatabaseService(ctx, sampleService(v1.ID, name)); err != nil {
			t.Fatalf("upsert %s: %v", name, err)
		}
	}
	if _, err := s.UpsertDatabaseService(ctx, sampleService(v2.ID, "other")); err != nil {
		t.Fatalf("upsert v2: %v", err)
	}

	list, err := s.ListDatabaseServices(ctx, v1.ID)
	if err != nil {
		t.Fatalf("ListDatabaseServices: %v", err)
	}
	want := []string{"alpha", "mu", "zeta"}
	if len(list) != len(want) {
		t.Fatalf("expected %d services, got %d", len(want), len(list))
	}
	for i, name := range want {
		if list[i].Name != name {
			t.Fatalf("expected ordered %v, got %s at %d", want, list[i].Name, i)
		}
	}

	// A different vault sees only its own service — no cross-vault leakage.
	other, _ := s.ListDatabaseServices(ctx, v2.ID)
	if len(other) != 1 || other[0].Name != "other" {
		t.Fatalf("expected v2 to see only its own service, got %+v", other)
	}
}

func TestDatabaseServiceDelete(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "db-delete")
	if _, err := s.UpsertDatabaseService(ctx, sampleService(ns.ID, "citus")); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Deleting an existing service reports true.
	deleted, err := s.DeleteDatabaseService(ctx, ns.ID, "citus")
	if err != nil {
		t.Fatalf("DeleteDatabaseService: %v", err)
	}
	if !deleted {
		t.Fatal("expected delete to report true for an existing service")
	}
	if _, err := s.GetDatabaseService(ctx, ns.ID, "citus"); err != sql.ErrNoRows {
		t.Fatalf("expected gone after delete, got %v", err)
	}

	// Deleting a missing service reports false, not an error.
	deleted, err = s.DeleteDatabaseService(ctx, ns.ID, "citus")
	if err != nil {
		t.Fatalf("second delete errored: %v", err)
	}
	if deleted {
		t.Fatal("expected false when deleting a missing service")
	}
}

func TestDatabaseServiceCascadeDeleteWithVault(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "db-cascade")
	if _, err := s.UpsertDatabaseService(ctx, sampleService(ns.ID, "alloy")); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := s.DeleteVault(ctx, "db-cascade"); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}

	// The FK cascade must have removed the service row along with the vault.
	list, err := s.ListDatabaseServices(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListDatabaseServices: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected services cascade-deleted, got %d", len(list))
	}
}

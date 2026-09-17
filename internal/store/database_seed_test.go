package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

func TestDatabaseSeedHistory(t *testing.T) { checkDatabaseSeedHistory(t, openTestDB(t)) }

func checkDatabaseSeedHistory(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	v, err := s.CreateVault(ctx, "seed-history-"+newUUID())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteVault(ctx, v.ID) })
	svc := sampleService(v.ID, "seeded")
	if added, err := s.SeedDatabaseService(ctx, svc); err != nil || !added {
		t.Fatalf("first seed: %v %v", added, err)
	}
	if removed, err := s.DeleteDatabaseService(ctx, v.ID, svc.Name); err != nil || !removed {
		t.Fatalf("delete: %v %v", removed, err)
	}
	if added, err := s.SeedDatabaseService(ctx, svc); err != nil || added {
		t.Fatalf("deleted seed resurrected: %v %v", added, err)
	}
	if _, err := s.GetDatabaseService(ctx, v.ID, svc.Name); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted seed available: %v", err)
	}
	if _, err := s.UpsertDatabaseService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if added, err := s.SeedDatabaseService(ctx, svc); err != nil || added {
		t.Fatalf("explicit re-add changed by seed: %v %v", added, err)
	}

	// Entries created through the API must also stay removed if a later
	// startup configuration happens to contain the same name.
	api := sampleService(v.ID, "api-created")
	if _, err := s.UpsertDatabaseService(ctx, api); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteDatabaseService(ctx, v.ID, api.Name); err != nil {
		t.Fatal(err)
	}
	if added, err := s.SeedDatabaseService(ctx, api); err != nil || added {
		t.Fatalf("API removal lost: %v %v", added, err)
	}

	// A failed initial seed must roll back its marker so a corrected entry
	// can be bootstrapped normally, without a manual database repair.
	invalid := sampleService(v.ID, "retry")
	invalid.SSLMode = "invalid-mode"
	if _, err := s.SeedDatabaseService(ctx, invalid); err == nil {
		t.Fatal("invalid seed succeeded")
	}
	invalid.SSLMode = "require"
	if added, err := s.SeedDatabaseService(ctx, invalid); err != nil || !added {
		t.Fatalf("failed seed consumed marker: %v %v", added, err)
	}

	// Live edits are preserved when configuration first encounters a name.
	live := sampleService(v.ID, "edited")
	live.Role = "runtime-edit"
	if _, err := s.UpsertDatabaseService(ctx, live); err != nil {
		t.Fatal(err)
	}
	live.Role = "config-role"
	if added, err := s.SeedDatabaseService(ctx, live); err != nil || added {
		t.Fatalf("existing service seeded: %v %v", added, err)
	}
	got, err := s.GetDatabaseService(ctx, v.ID, live.Name)
	if err != nil || got.Role != "runtime-edit" {
		t.Fatalf("live edit overwritten: %+v %v", got, err)
	}

	// Whichever transaction wins, an explicit removal must prevent a
	// concurrent bootstrap from leaving a live binding behind.
	for i := range 10 {
		concurrent := sampleService(v.ID, fmt.Sprintf("concurrent-%d", i))
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() { <-start; _, err := s.SeedDatabaseService(ctx, concurrent); results <- err }()
		go func() { <-start; _, err := s.DeleteDatabaseService(ctx, v.ID, concurrent.Name); results <- err }()
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.GetDatabaseService(ctx, v.ID, concurrent.Name); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("concurrent deletion lost: %v", err)
		}
	}
}

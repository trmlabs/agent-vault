package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditBootCounter(t *testing.T) { checkAuditBoots(t, openTestDB(t)) }

func checkAuditBoots(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	replica := "audit-test-" + time.Now().Format("150405.000000000")
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM audit_chain_replica WHERE replica = ?`), replica)
	})
	boot, previous, err := s.BeginAuditBoot(ctx, replica)
	if err != nil || boot != 1 || previous != (AuditBoot{}) {
		t.Fatalf("first boot: %d %+v %v", boot, previous, err)
	}
	if err := s.RecordAuditCheckpoint(ctx, replica, 1, 4, "mac-four"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAuditCheckpoint(ctx, replica, 1, 3, "mac-three"); err == nil {
		t.Fatal("older checkpoint replaced a newer one")
	}
	boot, previous, err = s.BeginAuditBoot(ctx, replica)
	if err != nil || boot != 2 || previous != (AuditBoot{Boot: 1, CheckpointSeq: 4, CheckpointMAC: "mac-four"}) {
		t.Fatalf("second boot: %d %+v %v", boot, previous, err)
	}
	if err := s.RecordAuditCheckpoint(ctx, replica, 1, 9, "stale"); err == nil {
		t.Fatal("superseded boot recorded a checkpoint")
	}
	boot, previous, err = s.BeginAuditBoot(ctx, replica)
	if err != nil || boot != 3 || previous != (AuditBoot{Boot: 2}) {
		t.Fatalf("boot after one without checkpoints: %d %+v %v", boot, previous, err)
	}
	if _, _, err := s.BeginAuditBoot(ctx, ""); err == nil {
		t.Fatal("empty replica accepted")
	}
}

func TestAuditBootSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	for want := uint64(1); want <= 2; want++ {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if boot, _, err := s.BeginAuditBoot(ctx, "broker-0"); err != nil || boot != want {
			t.Fatalf("boot %d after reopen: %d %v", want, boot, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The store's heads are what an export is checked against: each replica's
// current boot and its newest persisted checkpoint.
func TestAuditHeadsListEveryReplica(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	for _, replica := range []string{"broker-1", "broker-0"} {
		if _, _, err := s.BeginAuditBoot(ctx, replica); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.BeginAuditBoot(ctx, "broker-0"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAuditCheckpoint(ctx, "broker-0", 2, 7, "mac-seven"); err != nil {
		t.Fatal(err)
	}
	heads, err := s.ListAuditHeads(ctx)
	want := []AuditHead{{Replica: "broker-0", Boot: 2, CheckpointSeq: 7, CheckpointMAC: "mac-seven"}, {Replica: "broker-1", Boot: 1}}
	if err != nil || len(heads) != 2 || heads[0] != want[0] || heads[1] != want[1] {
		t.Fatalf("heads %+v %v, want %+v", heads, err, want)
	}
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AuditBoot is a replica's previous audit boot and the last checkpoint row it
// persisted. A zero Boot means the replica has never booted.
type AuditBoot struct {
	Boot          uint64
	CheckpointSeq uint64
	CheckpointMAC string
}

// BeginAuditBoot advances the replica's boot counter and returns the boot it
// replaces. Concurrent starts under one replica name cannot share a number.
func (s *SQLStore) BeginAuditBoot(ctx context.Context, replica string) (uint64, AuditBoot, error) {
	if replica == "" {
		return 0, AuditBoot{}, fmt.Errorf("audit replica name is required")
	}
	var previous AuditBoot
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		var seq int64
		var boot int64
		err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT boot, checkpoint_seq, checkpoint_mac FROM audit_chain_replica WHERE replica = ?`), replica).Scan(&boot, &seq, &previous.CheckpointMAC)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO audit_chain_replica (replica, boot) VALUES (?, 1)`), replica)
			return err
		case err != nil:
			return err
		}
		previous.Boot, previous.CheckpointSeq = uint64(boot), uint64(seq)
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE audit_chain_replica SET boot = ?, checkpoint_seq = 0, checkpoint_mac = '' WHERE replica = ? AND boot = ?`), boot+1, replica, boot)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("audit boot advanced concurrently")
		}
		return nil
	})
	if err != nil {
		return 0, AuditBoot{}, err
	}
	return previous.Boot + 1, previous, nil
}

// RecordAuditCheckpoint persists the newest checkpoint row of the current
// boot. It fails if another process has since taken the replica name.
func (s *SQLStore) RecordAuditCheckpoint(ctx context.Context, replica string, boot, seq uint64, mac string) error {
	if replica == "" || boot == 0 || mac == "" {
		return fmt.Errorf("incomplete audit checkpoint")
	}
	return s.auditWrite(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE audit_chain_replica SET checkpoint_seq = ?, checkpoint_mac = ? WHERE replica = ? AND boot = ? AND checkpoint_seq < ?`), int64(seq), mac, replica, int64(boot), int64(seq))
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("audit boot no longer current")
		}
		return nil
	})
}

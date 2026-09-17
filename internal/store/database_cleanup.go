package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DatabaseCleanup stores only a revocation reference, never a token or password.
type DatabaseCleanup struct{ Accessor, Binding, LeaseID string }

func (s *SQLStore) databaseCleanupExec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	// Share the committed, synchronous write boundary with the audit journal.
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

// ClaimDatabaseCleanupOwner fences the single PostgreSQL broker. Expired claims
// can be recovered after a crash; a running owner must renew before expiry.
func (s *SQLStore) ClaimDatabaseCleanupOwner(ctx context.Context, owner string, now, until time.Time) error {
	if owner == "" || !until.After(now) {
		return fmt.Errorf("invalid database cleanup owner")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup_owner (id, owner, expires_ns) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, expires_ns = excluded.expires_ns
		WHERE database_cleanup_owner.expires_ns <= ?`), owner, until.UnixNano(), now.UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("database cleanup already owned by another broker")
	}
	return nil
}

func (s *SQLStore) RenewDatabaseCleanupOwner(ctx context.Context, owner string, now, until time.Time) error {
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup_owner SET expires_ns = ? WHERE id = 1 AND owner = ? AND expires_ns > ?`), until.UnixNano(), owner, now.UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("database cleanup ownership lost")
	}
	return nil
}

func (s *SQLStore) ReleaseDatabaseCleanupOwner(ctx context.Context, owner string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup_owner WHERE id = 1 AND owner = ?`), owner)
	return err
}

func (s *SQLStore) AddDatabaseCleanup(ctx context.Context, owner string, record DatabaseCleanup) error {
	if record.Accessor == "" || record.Binding == "" {
		return fmt.Errorf("incomplete database cleanup record")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup (accessor, binding)
		SELECT ?, ? FROM database_cleanup_owner WHERE id = 1 AND owner = ? AND expires_ns > ?`), record.Accessor, record.Binding, owner, time.Now().UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("database cleanup ownership lost")
	}
	return nil
}

func (s *SQLStore) ListDatabaseCleanup(ctx context.Context) ([]DatabaseCleanup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT accessor, binding, lease_id FROM database_cleanup WHERE reconciliation_evidence = '' ORDER BY accessor`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var records []DatabaseCleanup
	for rows.Next() {
		var record DatabaseCleanup
		if err := rows.Scan(&record.Accessor, &record.Binding, &record.LeaseID); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLStore) SetDatabaseCleanupLease(ctx context.Context, owner, accessor, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("database lease ID is required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET lease_id = ? WHERE accessor = ? AND reconciliation_evidence = '' AND EXISTS
		(SELECT 1 FROM database_cleanup_owner WHERE id = 1 AND owner = ? AND expires_ns > ?)`), leaseID, accessor, owner, time.Now().UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("database cleanup ownership or record lost")
	}
	return nil
}

// ConfirmDatabaseCleanup is an explicit operator attestation, not an automated
// test result. Keep its evidence after removing the binding's quarantine.
func (s *SQLStore) ConfirmDatabaseCleanup(ctx context.Context, owner, accessor, evidence string) error {
	if strings.TrimSpace(accessor) == "" || strings.TrimSpace(evidence) == "" {
		return fmt.Errorf("accessor and database reconciliation evidence are required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET reconciliation_evidence = ? WHERE accessor = ? AND lease_id = '' AND reconciliation_evidence = '' AND EXISTS
		(SELECT 1 FROM database_cleanup_owner WHERE id = 1 AND owner = ? AND expires_ns > ?)`), evidence, accessor, owner, time.Now().UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("unknown-issuance record not found")
	}
	return nil
}

func (s *SQLStore) DeleteDatabaseCleanup(ctx context.Context, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup WHERE accessor = ?`), accessor)
	return err
}

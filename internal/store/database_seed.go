package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SeedDatabaseService consumes a bootstrap entry once. The durable marker
// survives deletion; explicit API additions remain possible through Upsert.
func (s *SQLStore) SeedDatabaseService(ctx context.Context, svc DatabaseService) (bool, error) {
	var inserted bool
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO database_service_seed_history (vault_id, name)
			VALUES (?, ?) ON CONFLICT(vault_id, name) DO NOTHING`), svc.VaultID, svc.Name)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		if svc.SSLMode == "" {
			svc.SSLMode = "prefer"
		}
		now := s.dialect.FormatTime(time.Now().UTC())
		res, err = tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO database_services (`+databaseServiceColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(vault_id, name) DO NOTHING`),
			newUUID(), svc.VaultID, svc.Name, svc.Upstream, svc.Database, svc.Mount, svc.Role, svc.SSLMode, svc.MaxConns, now, now)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		inserted = n > 0
		return err
	})
	if err != nil {
		return false, fmt.Errorf("seeding database service: %w", err)
	}
	return inserted, nil
}

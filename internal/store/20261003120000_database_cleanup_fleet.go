package store

import "gorm.io/gorm"

// Broker fleet: one owner row per running broker process, expiring by the
// database clock, and an owner on every cleanup record so a survivor can claim
// a dead replica's records. Records from before this migration have no owner
// and are claimed by the first live broker. The single-owner table stays in
// place, unused, so the migration only adds.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS database_cleanup_replica (
			owner TEXT PRIMARY KEY, expires_ms BIGINT NOT NULL
		)`).Error; err != nil {
			return err
		}
		for _, column := range []struct{ name, ddl string }{
			{"owner", `ALTER TABLE database_cleanup ADD COLUMN owner TEXT NOT NULL DEFAULT ''`},
			{"quarantined", `ALTER TABLE database_cleanup ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0`},
		} {
			if db.Migrator().HasColumn("database_cleanup", column.name) {
				continue
			}
			if err := db.Exec(column.ddl).Error; err != nil {
				return err
			}
		}
		if err := db.Exec(`CREATE INDEX IF NOT EXISTS database_cleanup_owner_idx ON database_cleanup (owner)`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS broker_sessions (
			id TEXT PRIMARY KEY, owner TEXT NOT NULL, pod TEXT NOT NULL
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS broker_sessions_pod_idx ON broker_sessions (pod)`).Error
	})
}

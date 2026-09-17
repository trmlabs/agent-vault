package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS database_cleanup (
			accessor TEXT PRIMARY KEY, binding TEXT NOT NULL,
			lease_id TEXT NOT NULL DEFAULT '', reconciliation_evidence TEXT NOT NULL DEFAULT ''
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE TABLE IF NOT EXISTS database_cleanup_owner (
			id INTEGER PRIMARY KEY CHECK (id = 1), owner TEXT NOT NULL, expires_ns BIGINT NOT NULL
		)`).Error
	})
}

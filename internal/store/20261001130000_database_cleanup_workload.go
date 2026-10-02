package store

import "gorm.io/gorm"

// Attribute each cleanup record to the runtime instance (Pod UID) whose
// connection minted it, so a retired instance can be confirmed clean while its
// agent keeps serving. Empty means unattributed within the record's actor.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("database_cleanup", "workload_id") {
			return nil
		}
		return db.Exec(`ALTER TABLE database_cleanup ADD COLUMN workload_id TEXT NOT NULL DEFAULT ''`).Error
	})
}

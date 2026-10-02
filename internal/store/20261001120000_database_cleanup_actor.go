package store

import "gorm.io/gorm"

// Attribute each cleanup record to the actor whose connection minted it. Rows
// written before this column existed keep an empty actor and count against
// every actor, so per-actor admission stays fail closed for legacy records.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("database_cleanup", "actor_id") {
			return nil
		}
		return db.Exec(`ALTER TABLE database_cleanup ADD COLUMN actor_id TEXT NOT NULL DEFAULT ''`).Error
	})
}

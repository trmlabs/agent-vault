package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS database_service_seed_history (
			vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			PRIMARY KEY (vault_id, name)
		)`).Error
	})
}

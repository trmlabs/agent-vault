package store

import "gorm.io/gorm"

// When each proxy binding's activity history began: its first report, never
// pruned. The idle janitor deletes nothing until a scope's history covers the
// whole idle window, so a new, recreated or emptied scope is not read as
// "nobody used anything".
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS proxy_activity_scope (
			scope TEXT PRIMARY KEY, history_started_ms BIGINT NOT NULL
		)`).Error
	})
}

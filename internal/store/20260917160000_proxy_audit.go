package store

import "gorm.io/gorm"

// Independent of request_logs retention and identity/service lifetimes: deleting
// configuration must not erase an already acknowledged audit attempt.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS credential_proxy_audit (
   request_id TEXT PRIMARY KEY,
   vault_id TEXT NOT NULL,
   actor_type TEXT NOT NULL,
   actor_id TEXT NOT NULL,
   workload_id TEXT NOT NULL,
   destination TEXT NOT NULL,
   service TEXT NOT NULL,
   mapping_ids TEXT NOT NULL,
   method TEXT NOT NULL,
   decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
   outcome TEXT NOT NULL DEFAULT 'unknown' CHECK (outcome IN ('unknown','completed','denied','upstream_error')),
   status INTEGER NOT NULL DEFAULT 0 CHECK (status = 0 OR status BETWEEN 100 AND 599),
   started_at TEXT NOT NULL,
   finished_at TEXT
  )`).Error
	})
}

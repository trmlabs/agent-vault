package store

import "gorm.io/gorm"

// Runner session pins: a Claude runner session token (by its hash, never the
// token) and the Pod that first presented it, until the token expires. Every
// broker replica reads the same pins, so a token copied to another Pod is
// refused fleet-wide.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS runner_session_binding (
			token TEXT PRIMARY KEY, pod TEXT NOT NULL, expires_ms BIGINT NOT NULL
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS runner_session_binding_expires_idx ON runner_session_binding (expires_ms)`).Error
	})
}

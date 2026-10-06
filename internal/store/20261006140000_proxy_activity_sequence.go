package store

import "gorm.io/gorm"

// A sequence per proxy binding, one higher for every report the broker
// accepts. A proxy remembers the last number acknowledged to it; a later
// report carrying a number the store no longer reaches means the store lost
// writes (a restore to an earlier point), and the binding's history restarts.
// A row written before the column existed starts at 0: the next report
// carrying any acknowledged number reads as a loss, which fails closed.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("proxy_activity_scope", "seq") {
			return nil
		}
		return db.Exec(`ALTER TABLE proxy_activity_scope ADD COLUMN seq BIGINT NOT NULL DEFAULT 0`).Error
	})
}

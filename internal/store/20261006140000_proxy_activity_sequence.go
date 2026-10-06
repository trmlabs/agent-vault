package store

import "gorm.io/gorm"

// A report stream per proxy replica within a binding: a sequence that each
// report the replica gets accepted advances by one. A replica remembers the
// last number acknowledged to it; a later report carrying a number its stream
// no longer reaches, or a stream that is gone, means the store lost writes
// (a restore to an earlier point) and the binding's history restarts. Only the
// replica itself advances its stream, so another replica's reports cannot
// overtake a loss. Streams unused for the retention time are pruned.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS proxy_activity_stream (
			scope TEXT NOT NULL, replica TEXT NOT NULL, seq BIGINT NOT NULL, used_ms BIGINT NOT NULL,
			PRIMARY KEY (scope, replica)
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS proxy_activity_stream_used_idx ON proxy_activity_stream (used_ms)`).Error
	})
}

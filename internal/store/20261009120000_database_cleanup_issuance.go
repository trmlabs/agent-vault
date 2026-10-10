package store

import "gorm.io/gorm"

// Record what an automatic check of an unknown issuance needs: the Vault
// mount and role the credential was read from, when its child token expires,
// and when this process revoked that token, both by the database clock.
// Records from before this migration have no mount or role, so they keep
// waiting for an operator.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		for _, column := range []struct{ name, ddl string }{
			{"mount", `ALTER TABLE database_cleanup ADD COLUMN mount TEXT NOT NULL DEFAULT ''`},
			{"role", `ALTER TABLE database_cleanup ADD COLUMN role TEXT NOT NULL DEFAULT ''`},
			{"token_expires_ms", `ALTER TABLE database_cleanup ADD COLUMN token_expires_ms BIGINT NOT NULL DEFAULT 0`},
			{"token_revoked_ms", `ALTER TABLE database_cleanup ADD COLUMN token_revoked_ms BIGINT NOT NULL DEFAULT 0`},
		} {
			if db.Migrator().HasColumn("database_cleanup", column.name) {
				continue
			}
			if err := db.Exec(column.ddl).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

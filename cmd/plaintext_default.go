//go:build !e2e

package cmd

import "log/slog"

// testPlaintextDatabases does nothing in a production build: catalog
// databases are reached with verify-full whatever the environment says, and
// a set AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES is reported and ignored.
func testPlaintextDatabases(getenv func(string) string, logger *slog.Logger) {
	if getenv("AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES") != "" {
		logger.Error("broker catalog: AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES is ignored; this binary is not an e2e build")
	}
}

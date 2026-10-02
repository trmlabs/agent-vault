//go:build e2e

package cmd

import (
	"log/slog"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// testPlaintextDatabases honours AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES in
// the e2e build only, for the Kind fixture database, which serves no TLS.
func testPlaintextDatabases(getenv func(string) string, logger *slog.Logger) {
	if v := getenv("AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES"); v == "1" || v == "true" {
		httpcatalog.AllowPlaintextDatabases()
		logger.Warn("broker catalog: e2e build; plaintext database entries for cluster Services allowed")
	}
}

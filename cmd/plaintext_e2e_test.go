//go:build e2e

package cmd

import (
	"log/slog"
	"testing"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const plaintextCatalog = `{"entries":[{"name":"fixture","kind":"postgres","host":"fixture-db.gatehouse.svc.cluster.local","pools":["pool-a"],
	"postgres":{"database":"appdb","mount":"database","role":"staging.us.fixture.appdb-readonly","sslmode":"disable"}}]}`

// The e2e build, and only it, lets the Kind fixture's TLS-less database be
// reached in plaintext.
func TestE2EBuildAllowsPlaintextForClusterServices(t *testing.T) {
	testPlaintextDatabases(func(k string) string {
		if k == "AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES" {
			return "1"
		}
		return ""
	}, slog.New(slog.DiscardHandler))
	if _, err := httpcatalog.Parse([]byte(plaintextCatalog)); err != nil {
		t.Fatalf("e2e build refused the fixture database: %v", err)
	}
}

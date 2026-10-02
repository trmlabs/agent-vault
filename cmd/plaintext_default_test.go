//go:build !e2e

package cmd

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const plaintextCatalog = `{"entries":[{"name":"fixture","kind":"postgres","host":"fixture-db.gatehouse.svc.cluster.local","pools":["pool-a"],
	"postgres":{"database":"appdb","mount":"database","role":"staging.us.fixture.appdb-readonly","sslmode":"disable"}}]}`

// A production build has no way to turn on plaintext databases: the switch
// is reported and ignored, and sslmode disable is refused even for a cluster
// Service host.
func TestProductionBuildRefusesPlaintextDatabases(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	var logs bytes.Buffer
	testPlaintextDatabases(func(k string) string {
		if k == "AGENT_VAULT_CATALOG_PLAINTEXT_DATABASES" {
			return "1"
		}
		return ""
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "ignored") {
		t.Fatalf("the ignored switch was not reported: %q", logs.String())
	}
	if _, err := httpcatalog.Parse([]byte(plaintextCatalog)); err == nil || !strings.Contains(err.Error(), "sslmode") {
		t.Fatalf("a production build accepted sslmode disable: %v", err)
	}
}

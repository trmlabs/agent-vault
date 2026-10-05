package cmd

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
)

// A database broker that was asked for but has no Vault login fails startup,
// so the replica never reports ready without a way to mint credentials.
func TestPostgresBrokerWithoutVaultFailsStartup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	t.Setenv("AGENT_VAULT_DB_SERVICES", "")
	t.Setenv("AGENT_VAULT_DB_SERVICES_FILE", "")
	t.Setenv("AGENT_VAULT_DB_BROKER", "")
	if err := attachPostgresBrokerIfEnabled(s, "127.0.0.1", 15432, logger); err != nil {
		t.Fatalf("broker not asked for: %v", err)
	}
	t.Setenv("AGENT_VAULT_DB_BROKER", "1")
	err := attachPostgresBrokerIfEnabled(s, "127.0.0.1", 15432, logger)
	if err == nil || !strings.Contains(err.Error(), "requires a working HashiCorp Vault client") {
		t.Fatalf("broker without Vault: %v", err)
	}
}

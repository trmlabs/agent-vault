package cmd

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/pgproxy"
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

// Admission settings are parsed strictly: a malformed value fails startup
// instead of being ignored.
func TestAdmissionSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	var opts pgproxy.Options
	if err := applyAdmissionSettings(&opts, env(map[string]string{"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "512",
		"AGENT_VAULT_DB_ADMISSION_TIMEOUT": "3s", "AGENT_VAULT_DB_LEDGER_TIMEOUT": "6s"})); err != nil {
		t.Fatal(err)
	}
	if opts.AdmissionConcurrency != 512 || opts.AdmissionTimeout != 3*time.Second || opts.LedgerTimeout != 6*time.Second {
		t.Fatalf("settings %+v", opts)
	}
	for name, value := range map[string]string{
		"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "lots", "AGENT_VAULT_DB_ADMISSION_TIMEOUT": "2", "AGENT_VAULT_DB_LEDGER_TIMEOUT": "-1s",
	} {
		if err := applyAdmissionSettings(&pgproxy.Options{}, env(map[string]string{name: value})); err == nil {
			t.Errorf("%s=%s accepted", name, value)
		}
	}
	if err := applyAdmissionSettings(&pgproxy.Options{}, env(map[string]string{"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "0"})); err == nil {
		t.Error("a concurrency of 0 accepted")
	}
}

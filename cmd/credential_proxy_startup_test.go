package cmd

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
)

func TestCredentialProxyRejectsUnsafeStartupSettings(t *testing.T) {
	for _, tc := range []struct {
		name, enabled, identity, skip, address string
		port                                   int
		want                                   string
	}{
		{name: "invalid-toggle", enabled: "tru", want: "must be true or false"},
		{name: "missing-identity", enabled: "true", want: "requires workload identity"},
		{name: "skip-verification", enabled: "true", identity: "unused", skip: "true", want: "forbids VAULT_SKIP_VERIFY"},
		{name: "disabled-listener", enabled: "true", identity: "unused", want: "requires its HTTP proxy listener"},
		{name: "remote-plaintext-vault", enabled: "true", identity: "unused", port: 14322, address: "http://vault.example.test", want: "requires Vault TLS"},
		{name: "userinfo-vault", enabled: "true", identity: "unused", port: 14322, address: "https://user:credential@vault.example.test", want: "valid Vault address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_CREDENTIAL_PROXY", tc.enabled)
			t.Setenv("AGENT_VAULT_WORKLOAD_IDENTITY_FILE", tc.identity)
			t.Setenv("VAULT_SKIP_VERIFY", tc.skip)
			t.Setenv("VAULT_ADDR", tc.address)
			logger := slog.New(slog.DiscardHandler)
			s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
			err := attachServerExtensions(s, "127.0.0.1", tc.port, 0, make([]byte, 32), nil, logger, 0, 0)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup error %v", err)
			}
		})
	}
}

package cmd

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
)

// Proxy certificates are all-or-nothing, and need the cross-cluster
// listener, workload identity and Vault: a half setting fails startup.
func TestProxyCertificateSettingsAreAllOrNothing(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"unset":       {map[string]string{}, ""},
		"mount only":  {map[string]string{"AGENT_VAULT_PROXY_PKI_MOUNT": "pki"}, "need AGENT_VAULT_PROXY_PKI_MOUNT"},
		"ttl only":    {map[string]string{"AGENT_VAULT_PROXY_CERT_TTL": "24h"}, "need AGENT_VAULT_PROXY_PKI_MOUNT"},
		"no listener": {map[string]string{"AGENT_VAULT_PROXY_PKI_MOUNT": "pki", "AGENT_VAULT_PROXY_PKI_ROLE": "proxy", "AGENT_VAULT_PROXY_CERT_NAMES": "a.svc"}, "need the cross-cluster listener"},
	} {
		err := attachProxyCertificates(s, nil, logger, func(k string) string { return tc.env[k] })
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Proxy activity turns on with the cross-cluster listener and workload
// identity; its retention setting alone, or a bad one, fails startup.
func TestProxyActivitySettings(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	if err := attachProxyActivity(s, nil, nil, logger, func(string) string { return "" }); err != nil {
		t.Fatalf("unset: %v", err)
	}
	env := map[string]string{"AGENT_VAULT_PROXY_ACTIVITY_RETENTION": "24h"}
	if err := attachProxyActivity(s, nil, nil, logger, func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "cross-cluster") {
		t.Fatalf("retention without the listener: %v", err)
	}
}

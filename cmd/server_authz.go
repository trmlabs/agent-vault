package cmd

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// attachAuthorization wires the authorization model into the HTTP adapter:
//   - AGENT_VAULT_RUNNER_JWKS_URL (and AGENT_VAULT_RUNNER_ISSUER, default ccr)
//     verify Claude runner session tokens;
//   - AGENT_VAULT_ENTITLEMENTS selects the entitlement source: "file:<path>"
//     (fixtures and tests) or unset. Graph stays off until its Entra app
//     registration exists; "graph" is refused here until it is wired;
//   - AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS shortens the 5-minute cache.
//
// Without a verifier or a source, entries above T0 are refused on the pools
// that would need them.
func attachAuthorization(adapter *mitm.HeaderAdapter, getenv func(string) string) error {
	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}
	if url := getenv("AGENT_VAULT_RUNNER_JWKS_URL"); url != "" {
		if !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("AGENT_VAULT_RUNNER_JWKS_URL must be https")
		}
		issuer := getenv("AGENT_VAULT_RUNNER_ISSUER")
		if issuer == "" {
			issuer = "ccr"
		}
		adapter.Runner = &runnerid.Verifier{JWKSURL: url, Issuer: issuer, Client: client}
	}
	ttl := entitlement.MaxCacheTTL
	if raw := getenv("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 1 || time.Duration(seconds)*time.Second > entitlement.MaxCacheTTL {
			return fmt.Errorf("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS must be 1 to 300")
		}
		ttl = time.Duration(seconds) * time.Second
	}
	switch source := getenv("AGENT_VAULT_ENTITLEMENTS"); {
	case source == "":
	case strings.HasPrefix(source, "file:") && strings.HasPrefix(source, "file:/"):
		adapter.Entitlements = &entitlement.Cache{Source: entitlement.FileSource{Path: strings.TrimPrefix(source, "file:")}, TTL: ttl}
	case source == "graph":
		return fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs the Entra app registration (a Security decision) and is not enabled")
	default:
		return fmt.Errorf("AGENT_VAULT_ENTITLEMENTS must be unset or file:/absolute/path")
	}
	return nil
}

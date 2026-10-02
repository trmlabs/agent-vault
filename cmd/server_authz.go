package cmd

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// authorization is the runner verifier and entitlement cache, either of which
// may be nil.
type authorization struct {
	runner       *runnerid.Verifier
	entitlements *entitlement.Cache
}

// verifier returns the runner verifier as the interface consumers take, nil
// (not a typed nil) when unset.
func (a authorization) verifier() authorize.Verifier {
	if a.runner == nil {
		return nil
	}
	return a.runner
}

// attachAuthorization wires the authorization model into the HTTP adapter.
func attachAuthorization(adapter *mitm.HeaderAdapter, getenv func(string) string) error {
	a, err := loadAuthorization(getenv)
	if err != nil {
		return err
	}
	if a.runner != nil {
		adapter.Runner = a.runner
	}
	adapter.Entitlements = a.entitlements
	return nil
}

// loadAuthorization reads the authorization model's settings, shared by the
// HTTP adapter and the PostgreSQL broker:
//   - AGENT_VAULT_RUNNER_JWKS_URL (and AGENT_VAULT_RUNNER_ISSUER, default ccr)
//     verify Claude runner session tokens;
//   - AGENT_VAULT_ENTITLEMENTS selects the entitlement source: "file:<path>"
//     (fixtures and tests) or unset. Graph stays off until its Entra app
//     registration exists; "graph" is refused here until it is wired;
//   - AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS shortens the 5-minute cache.
//
// Without a verifier or a source, entries above T0 are refused on the pools
// that would need them.
func loadAuthorization(getenv func(string) string) (authorization, error) {
	var a authorization
	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}
	if url := getenv("AGENT_VAULT_RUNNER_JWKS_URL"); url != "" {
		if !strings.HasPrefix(url, "https://") {
			return a, fmt.Errorf("AGENT_VAULT_RUNNER_JWKS_URL must be https")
		}
		issuer := getenv("AGENT_VAULT_RUNNER_ISSUER")
		if issuer == "" {
			issuer = "ccr"
		}
		a.runner = &runnerid.Verifier{JWKSURL: url, Issuer: issuer, Client: client}
	}
	ttl := entitlement.MaxCacheTTL
	if raw := getenv("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 1 || time.Duration(seconds)*time.Second > entitlement.MaxCacheTTL {
			return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS must be 1 to 300")
		}
		ttl = time.Duration(seconds) * time.Second
	}
	switch source := getenv("AGENT_VAULT_ENTITLEMENTS"); {
	case source == "":
	case strings.HasPrefix(source, "file:") && strings.HasPrefix(source, "file:/"):
		a.entitlements = &entitlement.Cache{Source: entitlement.FileSource{Path: strings.TrimPrefix(source, "file:")}, TTL: ttl}
	case source == "graph":
		return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs the Entra app registration (a Security decision) and is not enabled")
	default:
		return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS must be unset or file:/absolute/path")
	}
	return a, nil
}

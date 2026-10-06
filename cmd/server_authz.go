package cmd

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// authorization is the Claude and Cursor verifiers and the entitlement cache,
// any of which may be nil.
type authorization struct {
	runner       *runnerid.Verifier
	cursor       *runnerid.CursorVerifier
	sandbox      []string // person domains for attested requesters
	entitlements *entitlement.Cache
}

// verifier returns the session verifiers as the interface consumers take, nil
// (not a typed nil) when none is set.
func (a authorization) verifier() authorize.Verifier {
	if a.runner == nil && a.cursor == nil && len(a.sandbox) == 0 {
		return nil
	}
	return runnerid.Verifiers{Claude: a.runner, Cursor: a.cursor, SandboxDomains: a.sandbox}
}

// attachAuthorization wires the authorization model into the HTTP adapter.
func attachAuthorization(adapter *mitm.HeaderAdapter, getenv func(string) string) error {
	a, err := loadAuthorization(getenv)
	if err != nil {
		return err
	}
	if v := a.verifier(); v != nil {
		adapter.Runner = v
	}
	adapter.Entitlements = a.entitlements
	return nil
}

// loadAuthorization reads the authorization model's settings, shared by the
// HTTP adapter and the PostgreSQL broker:
//   - AGENT_VAULT_RUNNER_JWKS_URL (and AGENT_VAULT_RUNNER_ISSUER, default ccr)
//     verify Claude runner session tokens;
//   - AGENT_VAULT_RUNNER_PERSON_DOMAINS lists the email domains (comma
//     separated, lower case) whose user sessions name a person, by act.email as
//     the Entra user principal name. Unset: no session names a person;
//   - AGENT_VAULT_CURSOR_AUDIENCE and AGENT_VAULT_CURSOR_TEAM_IDS (comma
//     separated) verify Cursor run identity tokens minted for that audience in
//     those teams; AGENT_VAULT_CURSOR_PERSON_DOMAINS names persons by
//     owner_email as AGENT_VAULT_RUNNER_PERSON_DOMAINS does for Claude.
//     AGENT_VAULT_CURSOR_JWKS_URL and AGENT_VAULT_CURSOR_ISSUER default to
//     Cursor's published ones;
//   - AGENT_VAULT_SANDBOX_PERSON_DOMAINS lists the email domains whose logins,
//     attested by a shared proxy from an agent Pod's requester annotation, name
//     a person, as the Entra user principal name. Unset: no attested login
//     names a person, and person-mode agent-sandbox pools are refused;
//   - AGENT_VAULT_ENTITLEMENTS selects the entitlement source: "file:<path>"
//     (fixtures and tests), "graph", or unset. "graph" asks Microsoft Graph,
//     looking the person up by user principal name, with a token from
//     workload identity federation and no secret: AGENT_VAULT_GRAPH_TENANT_ID
//     and AGENT_VAULT_GRAPH_CLIENT_ID (the Entra app) and
//     AGENT_VAULT_GRAPH_TOKEN_FILE (the projected service-account token,
//     audience api://AzureADTokenExchange) are all required;
//   - AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS shortens the 5-minute cache.
//
// Without a verifier or a source, entries above T0 are refused on the pools
// that would need them.
func loadAuthorization(getenv func(string) string) (authorization, error) {
	var a authorization
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: runnerid.RefuseRedirects,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}
	if url := getenv("AGENT_VAULT_RUNNER_JWKS_URL"); url != "" {
		if !strings.HasPrefix(url, "https://") {
			return a, fmt.Errorf("AGENT_VAULT_RUNNER_JWKS_URL must be https")
		}
		issuer := getenv("AGENT_VAULT_RUNNER_ISSUER")
		if issuer == "" {
			issuer = "ccr"
		}
		domains, err := personDomains("AGENT_VAULT_RUNNER_PERSON_DOMAINS", getenv)
		if err != nil {
			return a, err
		}
		a.runner = &runnerid.Verifier{JWKSURL: url, Issuer: issuer, PersonDomains: domains, Client: client}
	}
	sandbox, err := personDomains("AGENT_VAULT_SANDBOX_PERSON_DOMAINS", getenv)
	if err != nil {
		return a, err
	}
	a.sandbox = sandbox
	if audience := getenv("AGENT_VAULT_CURSOR_AUDIENCE"); audience != "" {
		cursor, err := cursorVerifier(audience, getenv, client)
		if err != nil {
			return a, err
		}
		a.cursor = cursor
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
		g, err := graphSource(getenv, client)
		if err != nil {
			return a, err
		}
		a.entitlements = &entitlement.Cache{Source: g, TTL: ttl}
	default:
		return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS must be unset, graph or file:/absolute/path")
	}
	return a, nil
}

// graphSource reads the Graph settings. Every one is required: a broker told to
// ask the directory that cannot fails at start, not at its first lookup.
func graphSource(getenv func(string) string, client *http.Client) (entitlement.GraphSource, error) {
	tenant, app, file := getenv("AGENT_VAULT_GRAPH_TENANT_ID"), getenv("AGENT_VAULT_GRAPH_CLIENT_ID"), getenv("AGENT_VAULT_GRAPH_TOKEN_FILE")
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(app) {
		return entitlement.GraphSource{}, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs AGENT_VAULT_GRAPH_TENANT_ID and AGENT_VAULT_GRAPH_CLIENT_ID as lower-case GUIDs")
	}
	if !strings.HasPrefix(file, "/") {
		return entitlement.GraphSource{}, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs AGENT_VAULT_GRAPH_TOKEN_FILE as an absolute path")
	}
	token := &entitlement.FederatedToken{TenantID: tenant, ClientID: app, AssertionFile: file, Client: client}
	return entitlement.GraphSource{Endpoint: entitlement.GraphEndpoint, Token: token.Token, Client: client}, nil
}

// cursorVerifier reads the Cursor settings. A Cursor audience without a team
// is refused: Cursor does not allowlist audiences, so the team is what keeps
// another company's runs out.
func cursorVerifier(audience string, getenv func(string) string, client *http.Client) (*runnerid.CursorVerifier, error) {
	if !audiencePattern.MatchString(audience) {
		return nil, fmt.Errorf("AGENT_VAULT_CURSOR_AUDIENCE must be printable with no spaces")
	}
	var teams []string
	for _, t := range strings.Split(getenv("AGENT_VAULT_CURSOR_TEAM_IDS"), ",") {
		if !teamPattern.MatchString(t) {
			return nil, fmt.Errorf("AGENT_VAULT_CURSOR_TEAM_IDS must be Cursor team IDs (decimal), comma separated")
		}
		teams = append(teams, t)
	}
	domains, err := personDomains("AGENT_VAULT_CURSOR_PERSON_DOMAINS", getenv)
	if err != nil {
		return nil, err
	}
	url, issuer := getenv("AGENT_VAULT_CURSOR_JWKS_URL"), getenv("AGENT_VAULT_CURSOR_ISSUER")
	if url == "" {
		url = runnerid.CursorJWKSURL
	}
	if issuer == "" {
		issuer = runnerid.CursorIssuer
	}
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("AGENT_VAULT_CURSOR_JWKS_URL must be https")
	}
	return &runnerid.CursorVerifier{JWKSURL: url, Issuer: issuer, Audience: audience, TeamIDs: teams, PersonDomains: domains, Client: client}, nil
}

// personDomains parses a person email domain list: lower-case DNS names only.
func personDomains(name string, getenv func(string) string) ([]string, error) {
	raw := getenv(name)
	if raw == "" {
		return nil, nil
	}
	var domains []string
	for _, d := range strings.Split(raw, ",") {
		if !domainPattern.MatchString(d) {
			return nil, fmt.Errorf("%s must be lower-case domain names, comma separated", name)
		}
		domains = append(domains, d)
	}
	return domains, nil
}

var (
	domainPattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	audiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}$`)
	teamPattern     = regexp.MustCompile(`^[0-9]{1,20}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// sessionBinder is the store's runner-session pin table, or nil when the
// store cannot hold one (claude-session pools then refuse every session).
func sessionBinder(st any) authorize.Binder {
	if b, ok := st.(authorize.Binder); ok {
		return b
	}
	return nil
}

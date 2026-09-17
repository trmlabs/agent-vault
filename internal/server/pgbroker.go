package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

// This file adapts Agent Vault's existing subsystems to the pgproxy broker's
// three dependency interfaces, so the PostgreSQL path reuses the same identity
// check as the HTTP proxy and the same HashiCorp Vault client, and resolves
// upstream databases from declarative configuration.

// agentAuthAdapter bridges the shared session resolver to pgproxy's
// AgentAuthenticator. A database connection is authorized by the agent's Agent
// Vault token exactly as an HTTP request is.
type agentAuthAdapter struct{ resolver brokercore.SessionResolver }

// NewAgentAuthAdapter wraps the session resolver for the PostgreSQL broker.
func NewAgentAuthAdapter(resolver brokercore.SessionResolver) pgproxy.AgentAuthenticator {
	return agentAuthAdapter{resolver: resolver}
}

func (a agentAuthAdapter) Authenticate(ctx context.Context, token, vaultHint string) (*pgproxy.AgentScope, error) {
	scope, err := a.resolver.ResolveForProxy(ctx, token, vaultHint)
	if err != nil {
		return nil, err
	}
	return &pgproxy.AgentScope{VaultID: scope.VaultID, VaultName: scope.VaultName, ActorID: scope.ActorID()}, nil
}

// DatabaseServiceConfig is one configured upstream database within a vault, as
// it appears in the declarative broker configuration.
type DatabaseServiceConfig struct {
	Name     string `json:"name"`                // service slug the agent selects by
	Upstream string `json:"upstream"`            // upstream host:port
	Database string `json:"database"`            // optional upstream database override
	Mount    string `json:"mount"`               // Vault database secrets-engine mount
	Role     string `json:"role"`                // Vault role granting scoped SQL privileges
	SSLMode  string `json:"sslmode,omitempty"`   // upstream TLS: disable|prefer(default)|require|verify-full
	MaxConns int    `json:"max_conns,omitempty"` // per-database connection budget (0 = broker default)
}

// staticDatabaseResolver resolves database services from a vault-name-keyed map
// built from configuration. Onboarding a database is a configuration change,
// not a code change.
type staticDatabaseResolver struct {
	byVault map[string][]pgproxy.DatabaseService
}

// NewStaticDatabaseResolver builds a resolver over a vault-name-keyed service
// map. Exact service names take precedence over unique upstream database aliases.
// Unknown names are rejected even when a vault has only one service.
func NewStaticDatabaseResolver(byVault map[string][]pgproxy.DatabaseService) pgproxy.DatabaseResolver {
	return staticDatabaseResolver{byVault: byVault}
}

func (r staticDatabaseResolver) ResolveDatabase(_ context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	svc, err := selectDatabaseService(r.byVault[scope.VaultName], scope.VaultName, requestedDatabase)
	if err != nil {
		return nil, err
	}
	for _, services := range r.byVault {
		for _, other := range services {
			if other.Addr == svc.Addr && other.MaxConns > 0 && (svc.MaxConns == 0 || other.MaxConns < svc.MaxConns) {
				svc.MaxConns = other.MaxConns
			}
		}
	}
	return svc, nil
}

// databaseServiceLister is the store capability the live resolver needs; the
// server's Store satisfies it, and it keeps the resolver unit-testable.
type databaseServiceLister interface {
	ListDatabaseServices(ctx context.Context, vaultID string) ([]store.DatabaseService, error)
	DatabaseUpstreamLimit(ctx context.Context, upstream string) (int, error)
}

// storeDatabaseResolver resolves database services from the store on each
// connection, so services added or removed through the management API take
// effect immediately without restarting the broker.
type storeDatabaseResolver struct{ store databaseServiceLister }

// NewStoreDatabaseResolver builds a live resolver backed by the store.
func NewStoreDatabaseResolver(lister databaseServiceLister) pgproxy.DatabaseResolver {
	return storeDatabaseResolver{store: lister}
}

func (r storeDatabaseResolver) ResolveDatabase(ctx context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	rows, err := r.store.ListDatabaseServices(ctx, scope.VaultID)
	if err != nil {
		return nil, fmt.Errorf("listing database services for vault %q: %w", scope.VaultName, err)
	}
	services := make([]pgproxy.DatabaseService, len(rows))
	for i, row := range rows {
		services[i] = pgproxy.DatabaseService{
			Name:     row.Name,
			Addr:     row.Upstream,
			Database: row.Database,
			Mount:    row.Mount,
			Role:     row.Role,
			SSLMode:  row.SSLMode,
			MaxConns: row.MaxConns,
		}
	}
	svc, err := selectDatabaseService(services, scope.VaultName, requestedDatabase)
	if err != nil {
		return nil, err
	}
	// All aliases/vaults pointing at one endpoint share its strictest explicit
	// limit. The broker's global cap also applies when every limit is default.
	svc.MaxConns, err = r.store.DatabaseUpstreamLimit(ctx, svc.Addr)
	if err != nil {
		return nil, fmt.Errorf("reading database budget: %w", err)
	}
	return svc, nil
}

// selectDatabaseService picks the service an agent is asking for within its
// vault. Exact names win; a database alias must be unique. The same strict
// selection applies to single-service vaults, so deleting a service cannot
// silently redirect reconnecting clients to another database.
func selectDatabaseService(services []pgproxy.DatabaseService, vaultName, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	for _, svc := range services {
		if svc.Name == requestedDatabase {
			return &svc, nil
		}
	}
	var match *pgproxy.DatabaseService
	for _, svc := range services {
		if svc.Database != "" && svc.Database == requestedDatabase {
			if match != nil {
				return nil, fmt.Errorf("ambiguous database alias %q; select a service name", requestedDatabase)
			}
			copy := svc
			match = &copy
		}
	}
	if match != nil {
		return match, nil
	}
	available := make([]string, len(services))
	for i := range services {
		available[i] = services[i].Name
	}
	return nil, fmt.Errorf("no database service named %q in vault %q (available: %s)", requestedDatabase, vaultName, strings.Join(available, ", "))
}

// DatabaseResolver returns a live, store-backed resolver for the PostgreSQL
// broker so database services added or removed through the management API take
// effect without a restart.
func (s *Server) DatabaseResolver() pgproxy.DatabaseResolver {
	return NewStoreDatabaseResolver(s.store)
}

// SeedDatabaseServices bootstraps the store from configuration (the
// AGENT_VAULT_DB_SERVICES map, keyed by vault name) on startup. It is
// insert-if-absent: a service already present in the store — including one
// edited through the management API — is left untouched, so config seeds an
// empty store without clobbering runtime changes on every restart. It returns
// the number of services newly seeded. A configured vault name that does not
// exist is skipped with a warning rather than failing startup.
func (s *Server) SeedDatabaseServices(ctx context.Context, byVault map[string][]pgproxy.DatabaseService) (int, error) {
	seeded := 0
	for vaultName, services := range byVault {
		vault, err := s.store.GetVault(ctx, vaultName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return seeded, fmt.Errorf("resolving seed vault: %w", err)
		}
		if vault == nil || errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("pgproxy: skipping seed for unknown vault", slog.String("vault", vaultName))
			continue
		}
		added, err := func() (int, error) {
			unlock, err := s.lockVaultServices(ctx, vault.ID)
			if err != nil {
				return 0, err
			}
			defer unlock()
			added := 0
			for _, svc := range services {
				switch _, err := s.store.GetDatabaseService(ctx, vault.ID, svc.Name); {
				case err == nil:
					continue // already present (config or runtime); do not clobber
				case !errors.Is(err, sql.ErrNoRows):
					return added, fmt.Errorf("checking database service %q in vault %q: %w", svc.Name, vaultName, err)
				}
				if _, err := s.store.UpsertDatabaseService(ctx, store.DatabaseService{
					VaultID:  vault.ID,
					Name:     svc.Name,
					Upstream: svc.Addr,
					Database: svc.Database,
					Mount:    svc.Mount,
					Role:     svc.Role,
					SSLMode:  svc.SSLMode,
					MaxConns: svc.MaxConns,
				}); err != nil {
					return added, fmt.Errorf("seeding database service %q in vault %q: %w", svc.Name, vaultName, err)
				}
				added++
			}
			return added, nil
		}()
		seeded += added
		if err != nil {
			return seeded, err
		}

	}
	return seeded, nil
}

// vaultLeaseMinter adapts the HashiCorp Vault client to pgproxy's LeaseMinter.
type vaultLeaseMinter struct{ client *hashicorp.Client }

// NewVaultLeaseMinter builds a minter over the Vault database secrets engine:
// each Mint issues a fresh dynamic credential, and Renew/Revoke manage its
// lease.
func NewVaultLeaseMinter(client *hashicorp.Client) pgproxy.LeaseMinter {
	return vaultLeaseMinter{client: client}
}

func (m vaultLeaseMinter) Mint(ctx context.Context, _ string, svc *pgproxy.DatabaseService) (*pgproxy.Lease, error) {
	issuedAt := time.Now()
	cred, err := m.client.ReadDatabaseCredential(ctx, svc.Mount, svc.Role)
	if err != nil {
		return nil, err
	}
	return &pgproxy.Lease{
		ID:        cred.LeaseID,
		Username:  cred.Username,
		Password:  cred.Password,
		ExpiresAt: cred.ExpiresAt(issuedAt),
		Renewable: cred.Renewable,
	}, nil
}

func (m vaultLeaseMinter) Renew(ctx context.Context, leaseID string, minRemaining time.Duration) (time.Time, error) {
	started := time.Now()
	granted, err := m.client.RenewLease(ctx, leaseID, minRemaining)
	if err != nil {
		return time.Time{}, err
	}
	return started.Add(granted), nil
}

func (m vaultLeaseMinter) Revoke(ctx context.Context, leaseID string) error {
	return m.client.RevokeLease(ctx, leaseID)
}

// LoadDatabaseServices reads the vault-name-keyed database-service map from the
// AGENT_VAULT_DB_SERVICES environment variable (inline JSON) or, when that is
// empty, from the file named by AGENT_VAULT_DB_SERVICES_FILE. It returns an
// empty map when neither is set. The wire form is:
//
//	{"<vault>": [{"name","upstream","database","mount","role"}, ...]}
func LoadDatabaseServices(getenv func(string) string) (map[string][]pgproxy.DatabaseService, error) {
	raw := strings.TrimSpace(getenv("AGENT_VAULT_DB_SERVICES"))
	if raw == "" {
		if path := strings.TrimSpace(getenv("AGENT_VAULT_DB_SERVICES_FILE")); path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read AGENT_VAULT_DB_SERVICES_FILE: %w", err)
			}
			raw = strings.TrimSpace(string(data))
		}
	}
	if raw == "" {
		return map[string][]pgproxy.DatabaseService{}, nil
	}

	var cfg map[string][]DatabaseServiceConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse database services JSON: %w", err)
	}
	out := make(map[string][]pgproxy.DatabaseService, len(cfg))
	for vault, entries := range cfg {
		for _, entry := range entries {
			if err := entry.Validate(vault); err != nil {
				return nil, err
			}
			for _, svc := range out[vault] {
				if svc.Name == entry.Name {
					return nil, fmt.Errorf("duplicate database service %q in vault %q", entry.Name, vault)
				}
			}
			out[vault] = append(out[vault], pgproxy.DatabaseService{
				Name:     entry.Name,
				Addr:     entry.Upstream,
				Database: entry.Database,
				Mount:    entry.Mount,
				Role:     entry.Role,
				SSLMode:  entry.SSLMode,
				MaxConns: entry.MaxConns,
			})
		}
	}
	return out, nil
}

var databaseServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Validate checks the shared API, CLI and bootstrap input contract.
func (e DatabaseServiceConfig) Validate(vault string) error {
	switch {
	case strings.TrimSpace(e.Name) == "":
		return fmt.Errorf("database service in vault %q is missing %q", vault, "name")
	case strings.TrimSpace(e.Upstream) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "upstream")
	case strings.TrimSpace(e.Mount) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "mount")
	case strings.TrimSpace(e.Role) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "role")
	}
	if !databaseServiceName.MatchString(e.Name) {
		return fmt.Errorf("database name must be 1-64 lowercase letters, digits or hyphens")
	}
	host, port, err := net.SplitHostPort(e.Upstream)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("upstream must be a nonempty host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("upstream port must be between 1 and 65535")
	}
	if err := hashicorp.ValidateDatabaseReference(e.Mount, e.Role); err != nil {
		return err
	}
	if e.MaxConns < 0 {
		return fmt.Errorf("database service %q in vault %q: max_conns %d must be >= 0 (0 = broker default)", e.Name, vault, e.MaxConns)
	}
	// Reject an unrecognized sslmode at config load rather than silently
	// downgrading to "prefer" — a typo must not quietly disable TLS.
	switch e.SSLMode {
	case "", "disable", "prefer", "require", "verify-full":
	default:
		return fmt.Errorf("database service %q in vault %q: invalid sslmode %q (want disable|prefer|require|verify-full)", e.Name, vault, e.SSLMode)
	}
	return nil
}

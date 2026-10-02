package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

// catalogDatabaseResolver resolves databases from the live catalog on every
// connection, so a database added to the catalog is reachable at the next
// reload without a broker restart. The requested database name selects the
// entry; the connecting pool must be granted it, and the requester must pass
// the same tier and entitlement decision as an HTTP request. The resolver runs
// again at every recheck, so the session token is re-verified and membership
// re-read (through the cache) for the life of the session.
type catalogDatabaseResolver struct {
	catalog      interface{ Current() httpcatalog.Catalog }
	runner       authorize.Verifier
	entitlements *entitlement.Cache
	sessions     authorize.Binder
}

// NewCatalogDatabaseResolver builds a resolver over a live catalog source.
// runner, entitlements and sessions may be nil; entries that need them are
// then refused.
func NewCatalogDatabaseResolver(catalog interface{ Current() httpcatalog.Catalog }, runner authorize.Verifier, entitlements *entitlement.Cache, sessions authorize.Binder) pgproxy.DatabaseResolver {
	return catalogDatabaseResolver{catalog: catalog, runner: runner, entitlements: entitlements, sessions: sessions}
}

func (r catalogDatabaseResolver) ResolveDatabase(ctx context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	catalog := r.catalog.Current()
	entry, err := catalog.Database(requestedDatabase, scope.Pool)
	switch {
	case errors.Is(err, httpcatalog.ErrPool):
		return nil, fmt.Errorf("database %q is not granted to this pool", requestedDatabase)
	case err != nil:
		return nil, fmt.Errorf("no database %q in the catalog", requestedDatabase)
	}
	pool, _ := catalog.Pool(scope.Pool) // undefined pools: no identity, ceiling T0
	who, refusal := authorize.Resolve(ctx, pool, pgproxy.Session(ctx), scope.WorkloadID, r.runner, r.sessions)
	record := pgproxy.Requester{Kind: who.Kind, Subject: who.Subject, TokenSHA256: who.TokenSHA256}
	if refusal == "" {
		d := authorize.Decide(ctx, r.entitlements, pool, *entry, who)
		record.Tier, record.Decision, record.ObjectID = d.Tier, d.Outcome, d.ObjectID
		record.Groups, record.CacheAgeSec = strings.Join(d.Groups, ","), int64(d.CacheAge.Seconds())
		if !d.Allowed {
			refusal = d.Outcome
		}
	}
	pgproxy.RecordRequester(ctx, record)
	if refusal != "" {
		return nil, &pgproxy.RefusedError{Outcome: refusal}
	}
	p := entry.Postgres
	svc := &pgproxy.DatabaseService{Name: entry.Name, Addr: net.JoinHostPort(entry.Host, strconv.Itoa(entry.Port)),
		Database: p.Database, Mount: p.Mount, Role: p.Role, SSLMode: p.SSLMode, MaxConns: p.MaxConns}
	// Entries on one endpoint share its strictest explicit budget, as the
	// store resolver does.
	for _, other := range catalog.Entries() {
		if other.Kind == "postgres" && other.Host == entry.Host && other.Port == entry.Port && other.Postgres.MaxConns > 0 &&
			(svc.MaxConns == 0 || other.Postgres.MaxConns < svc.MaxConns) {
			svc.MaxConns = other.Postgres.MaxConns
		}
	}
	return svc, nil
}

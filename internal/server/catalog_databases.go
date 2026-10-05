package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

// catalogDatabaseResolver resolves databases from the live catalog on every
// connection, so a database added to the catalog is reachable at the next
// reload without a broker restart. The requested database name selects the
// entry; the connecting pool must be granted it.
type catalogDatabaseResolver struct {
	catalog interface{ Current() httpcatalog.Catalog }
}

// NewCatalogDatabaseResolver builds a resolver over a live catalog source.
func NewCatalogDatabaseResolver(catalog interface{ Current() httpcatalog.Catalog }) pgproxy.DatabaseResolver {
	return catalogDatabaseResolver{catalog: catalog}
}

func (r catalogDatabaseResolver) ResolveDatabase(_ context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	catalog := r.catalog.Current()
	entry, err := catalog.Database(requestedDatabase, scope.Pool)
	switch {
	case errors.Is(err, httpcatalog.ErrPool):
		return nil, fmt.Errorf("database %q is not granted to this pool", requestedDatabase)
	case err != nil:
		return nil, fmt.Errorf("no database %q in the catalog", requestedDatabase)
	}
	p := entry.Postgres
	svc := &pgproxy.DatabaseService{Name: entry.Name, Addr: net.JoinHostPort(entry.Host, strconv.Itoa(entry.Port)),
		Database: p.Database, Mount: p.Mount, Role: p.Role, SSLMode: p.SSLMode, MaxConns: p.MaxConns, ReadOnly: p.Access != "write"}
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

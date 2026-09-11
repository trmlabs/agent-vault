package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/store"
)

// databaseServiceView is the API representation of a managed PostgreSQL-broker
// database. It carries only references (the Vault mount and role that mint
// credentials), never a database password — the broker never stores one.
type databaseServiceView struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
	Database string `json:"database,omitempty"`
	Mount    string `json:"mount"`
	Role     string `json:"role"`
	SSLMode  string `json:"sslmode"`
	MaxConns int    `json:"max_conns,omitempty"`
}

func toDatabaseServiceView(svc store.DatabaseService) databaseServiceView {
	return databaseServiceView{
		Name:     svc.Name,
		Upstream: svc.Upstream,
		Database: svc.Database,
		Mount:    svc.Mount,
		Role:     svc.Role,
		SSLMode:  svc.SSLMode,
		MaxConns: svc.MaxConns,
	}
}

// handleDatabasesList returns the vault's managed database services. Readable by
// any vault member so an agent operator can discover which databases are
// reachable; it exposes names and references only.
func (s *Server) handleDatabasesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	rows, err := s.store.ListDatabaseServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list databases")
		return
	}
	views := make([]databaseServiceView, len(rows))
	for i, row := range rows {
		views[i] = toDatabaseServiceView(row)
	}
	jsonOK(w, map[string]interface{}{"vault": name, "databases": views})
}

// handleDatabaseGet returns a single managed database service by name.
func (s *Server) handleDatabaseGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	dbName := r.PathValue("db")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	svc, err := s.store.GetDatabaseService(ctx, ns.ID, dbName)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Database %q not found in vault %q", dbName, name))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to get database")
		return
	}
	jsonOK(w, map[string]interface{}{"vault": name, "database": toDatabaseServiceView(*svc)})
}

// handleDatabaseUpsert adds or updates a managed database service. Owner-only.
// External bindings use the instance Vault identity and require an owner.
// The body is a DatabaseServiceConfig; it is validated with the same rules the
// bootstrap-config path uses, so the API and config cannot disagree. Upsert is
// idempotent by name — re-adding a name overwrites its coordinates. The change
// takes effect immediately because the broker resolves databases live from the
// store.
func (s *Server) handleDatabaseUpsert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}

	var cfg DatabaseServiceConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := cfg.Validate(name); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Serialize with the same per-vault lock the HTTP-service path uses so a
	// concurrent add/remove of the same name cannot interleave.
	unlock, err := s.lockVaultServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "lock failed")
		return
	}
	defer unlock()

	_, getErr := s.store.GetDatabaseService(ctx, ns.ID, cfg.Name)
	created := errors.Is(getErr, sql.ErrNoRows)
	if getErr != nil && !created {
		jsonError(w, http.StatusInternalServerError, "Failed to check database")
		return
	}

	svc, err := s.store.UpsertDatabaseService(ctx, store.DatabaseService{
		VaultID:  ns.ID,
		Name:     cfg.Name,
		Upstream: cfg.Upstream,
		Database: cfg.Database,
		Mount:    cfg.Mount,
		Role:     cfg.Role,
		SSLMode:  cfg.SSLMode,
		MaxConns: cfg.MaxConns,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to save database")
		return
	}

	s.captureEvent(r, "av.database-add", actor, map[string]string{"vault": name, "database": cfg.Name})
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	jsonStatus(w, status, map[string]interface{}{
		"vault":    name,
		"created":  created,
		"database": toDatabaseServiceView(*svc),
	})
}

// handleDatabaseRemove deletes a managed database service by name. Admin-only.
// Existing agent connections continue on their already-minted credentials until
// they close or the credential expires; new connections can no longer select
// the removed database.
func (s *Server) handleDatabaseRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	dbName := r.PathValue("db")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}
	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
		return
	}

	unlock, err := s.lockVaultServices(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "lock failed")
		return
	}
	defer unlock()

	removed, err := s.store.DeleteDatabaseService(ctx, ns.ID, dbName)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to remove database")
		return
	}
	if !removed {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Database %q not found in vault %q", dbName, name))
		return
	}

	s.captureEvent(r, "av.database-remove", actor, map[string]string{"vault": name, "database": dbName})
	jsonOK(w, map[string]interface{}{"vault": name, "removed": dbName})
}

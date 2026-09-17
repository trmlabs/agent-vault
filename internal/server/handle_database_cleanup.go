package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type databaseCleanupManagement interface {
	ListDatabaseCleanup(context.Context) ([]store.DatabaseCleanup, error)
}

func (s *Server) handleDatabaseCleanupList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	journal, ok := s.store.(databaseCleanupManagement)
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "Database cleanup storage unavailable")
		return
	}
	records, err := journal.ListDatabaseCleanup(r.Context())
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "Database cleanup storage unavailable")
		return
	}
	type view struct {
		Accessor string `json:"accessor"`
		Binding  string `json:"binding"`
		LeaseID  string `json:"lease_id,omitempty"`
		Unknown  bool   `json:"operator_reconciliation_required"`
	}
	rows := make([]view, 0, len(records))
	for _, record := range records {
		rows = append(rows, view{record.Accessor, record.Binding, record.LeaseID, record.LeaseID == ""})
	}
	jsonOK(w, map[string]any{"records": rows})
}

// Confirmation records an owner's assertion based on external database
// evidence. It never represents an automated role/session verification.
func (s *Server) handleDatabaseCleanupConfirm(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	journal, ok := s.pgLeaseCloser.(interface {
		ConfirmDatabaseCleanup(context.Context, string, string) error
	})
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "Active database cleanup owner required")
		return
	}
	var body struct {
		Evidence  string `json:"evidence_reference"`
		Confirmed bool   `json:"confirmed_no_database_roles_or_sessions"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&body); err != nil || !body.Confirmed || strings.TrimSpace(body.Evidence) == "" || len(body.Evidence) > 4096 {
		jsonError(w, http.StatusBadRequest, "Explicit database verification and an evidence reference are required")
		return
	}
	evidence, _ := json.Marshal(map[string]string{"actor_id": actor.ID, "actor_type": actor.Type, "confirmed_at": time.Now().UTC().Format(time.RFC3339Nano), "evidence_reference": body.Evidence, "verification": "manual_operator_assertion"})
	if err = journal.ConfirmDatabaseCleanup(r.Context(), r.PathValue("accessor"), string(evidence)); err != nil {
		jsonError(w, http.StatusConflict, "Unknown-issuance record could not be reconciled")
		return
	}
	jsonOK(w, map[string]any{"manual_assertion_recorded": true, "automated_verification": false})
}

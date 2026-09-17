package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

type cleanupManagementStore struct {
	*mockStore
	evidence map[string]string
}

type cleanupConfirmer struct{ journal *cleanupManagementStore }

func (c *cleanupConfirmer) Close(context.Context) error { return nil }
func (c *cleanupConfirmer) ConfirmDatabaseCleanup(ctx context.Context, accessor, evidence string) error {
	return c.journal.ConfirmDatabaseCleanup(ctx, accessor, evidence)
}

func (m *cleanupManagementStore) ListDatabaseCleanup(context.Context) ([]store.DatabaseCleanup, error) {
	return []store.DatabaseCleanup{{Accessor: "pending", Binding: "vault/db"}}, nil
}
func (m *cleanupManagementStore) ConfirmDatabaseCleanup(_ context.Context, accessor, evidence string) error {
	if accessor != "pending" {
		return fmt.Errorf("not found")
	}
	m.evidence[accessor] = evidence
	return nil
}

func TestDatabaseCleanupRequiresOwnerAndExplicitEvidence(t *testing.T) {
	srv, ms, admin, member := setupDatabaseAPITest(t)
	journal := &cleanupManagementStore{mockStore: ms, evidence: make(map[string]string)}
	srv.store = journal
	srv.pgLeaseCloser = &cleanupConfirmer{journal}
	for _, test := range []struct {
		name, token, accessor, body string
		want                        int
	}{
		{"member denied", member, "pending", `{"evidence_reference":"test","confirmed_no_database_roles_or_sessions":true}`, 403},
		{"missing confirmation", admin, "pending", `{"evidence_reference":"test"}`, 400},
		{"missing evidence", admin, "pending", `{"confirmed_no_database_roles_or_sessions":true}`, 400},
		{"wrong record", admin, "other", `{"evidence_reference":"test","confirmed_no_database_roles_or_sessions":true}`, 409},
		{"explicit owner assertion", admin, "pending", `{"evidence_reference":"https://example.test/recovery","confirmed_no_database_roles_or_sessions":true}`, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			req.SetPathValue("accessor", test.accessor)
			req = req.WithContext(context.WithValue(req.Context(), sessionContextKey, ms.sessions[test.token]))
			rec := httptest.NewRecorder()
			srv.handleDatabaseCleanupConfirm(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if len(journal.evidence) != 1 || !strings.Contains(journal.evidence["pending"], "manual_operator_assertion") || !strings.Contains(journal.evidence["pending"], "owner-user-id") {
		t.Fatal("operator attribution missing")
	}
}

func TestDatabaseCleanupConfirmationRequiresActiveMinter(t *testing.T) {
	srv, ms, admin, _ := setupDatabaseAPITest(t)
	srv.store = &cleanupManagementStore{mockStore: ms, evidence: make(map[string]string)}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"evidence_reference":"test","confirmed_no_database_roles_or_sessions":true}`))
	req = req.WithContext(context.WithValue(req.Context(), sessionContextKey, ms.sessions[admin]))
	rec := httptest.NewRecorder()
	srv.handleDatabaseCleanupConfirm(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("confirmation without minter status=%d", rec.Code)
	}
}

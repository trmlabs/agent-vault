package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestAgentIdentityExportOwnerOnlyAndStable(t *testing.T) {
	ms, owner := setupMockStoreWithSession(t)
	member := setupMemberSession(t, ms)
	agent := &store.Agent{ID: "immutable-bootstrap-agent", Name: "bootstrap-agent", Status: "active", CreatedBy: "member-user-id"}
	ms.agents[agent.Name] = agent
	session, err := ms.CreateAgentToken(context.Background(), agent.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(withStore(ms))
	for _, tc := range []struct {
		name, token string
		status      int
		wantID      bool
	}{
		{"owner", owner, http.StatusOK, true},
		{"visible-to-member", member, http.StatusOK, false},
		{"anonymous", "", http.StatusUnauthorized, false},
		{"invalid-session", "invalid-session", http.StatusUnauthorized, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/agents/bootstrap-agent", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d, want %d", rec.Code, tc.status)
			}
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			id, present := response["id"]
			if present != tc.wantID || tc.wantID && id != agent.ID {
				t.Fatal("immutable identifier missing or disclosed to non-owner")
			}
			if strings.Contains(rec.Body.String(), session.ID) {
				t.Fatal("identity export disclosed the agent credential")
			}
			if _, present := response["av_agent_token"]; present {
				t.Fatal("identity export returned a token field")
			}
		})
	}
	// Rename through the actual API, then confirm binding authority is unchanged.
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/bootstrap-agent/rename", strings.NewReader(`{"name":"renamed-agent"}`))
	req.Header.Set("Authorization", "Bearer "+owner)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/agents/renamed-agent", nil)
	req.Header.Set("Authorization", "Bearer "+owner)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || response.ID != "immutable-bootstrap-agent" {
		t.Fatal("renaming changed the exported workload binding identifier")
	}
}

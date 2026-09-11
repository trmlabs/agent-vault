package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// setupDatabaseAPITest builds a server with an admin session and a member
// session over the default vault (root-ns-id).
func setupDatabaseAPITest(t *testing.T) (srv *Server, ms *mockStore, adminToken, memberToken string) {
	t.Helper()
	ms = newMockStore()

	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess

	memberToken = setupMemberSession(t, ms, "root-ns-id")
	srv = newTestServer(withStore(ms))
	return srv, ms, adminSess.ID, memberToken
}

func doDatabaseRequest(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

const validDatabaseBody = `{"name":"alloy","upstream":"alloy.internal:5432","database":"appdb","mount":"database","role":"ro","sslmode":"require","max_conns":10}`

func TestDatabaseAPIAddListGetDelete(t *testing.T) {
	srv, ms, admin, _ := setupDatabaseAPITest(t)

	// Add: 201 Created.
	rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, validDatabaseBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var addResp struct {
		Created  bool `json:"created"`
		Database struct {
			Name, Upstream, Mount, Role, SSLMode string
			MaxConns                             int `json:"max_conns"`
		} `json:"database"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&addResp); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	if !addResp.Created || addResp.Database.Role != "ro" || addResp.Database.MaxConns != 10 {
		t.Fatalf("unexpected add response: %+v", addResp)
	}

	// It is persisted in the store under the vault id.
	if got, _ := ms.ListDatabaseServices(context.Background(), "root-ns-id"); len(got) != 1 || got[0].Name != "alloy" {
		t.Fatalf("expected one persisted service, got %+v", got)
	}

	// List includes it.
	rec = doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/default/databases", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var listResp struct {
		Databases []databaseServiceView `json:"databases"`
	}
	json.NewDecoder(rec.Body).Decode(&listResp)
	if len(listResp.Databases) != 1 || listResp.Databases[0].Name != "alloy" {
		t.Fatalf("unexpected list: %+v", listResp.Databases)
	}

	// Get one.
	rec = doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/default/databases/alloy", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Delete.
	rec = doDatabaseRequest(t, srv, http.MethodDelete, "/v1/vaults/default/databases/alloy", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got, _ := ms.ListDatabaseServices(context.Background(), "root-ns-id"); len(got) != 0 {
		t.Fatalf("expected service removed, got %+v", got)
	}
}

func TestDatabaseAPIUpsertIsIdempotent(t *testing.T) {
	srv, _, admin, _ := setupDatabaseAPITest(t)

	rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, validDatabaseBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first add: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Re-add the same name with changed coordinates: 200 (not created), overwritten.
	changed := `{"name":"alloy","upstream":"alloy.internal:6000","mount":"database","role":"rw","sslmode":"verify-full"}`
	rec = doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, changed)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-add: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Created  bool                `json:"created"`
		Database databaseServiceView `json:"database"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Created {
		t.Fatal("re-add should report created=false")
	}
	if resp.Database.Role != "rw" || resp.Database.Upstream != "alloy.internal:6000" {
		t.Fatalf("expected overwritten coordinates, got %+v", resp.Database)
	}

	// Still exactly one row.
	rec = doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/default/databases", admin, "")
	var listResp struct {
		Databases []databaseServiceView `json:"databases"`
	}
	json.NewDecoder(rec.Body).Decode(&listResp)
	if len(listResp.Databases) != 1 {
		t.Fatalf("expected exactly one row after re-add, got %d", len(listResp.Databases))
	}
}

// TestDatabaseAPIDefaultsEmptySSLMode pins the documented default: adding a
// database without sslmode succeeds and stores "prefer" (the store's CHECK
// rejects an empty value, so an unnormalized empty would 500).
func TestDatabaseAPIDefaultsEmptySSLMode(t *testing.T) {
	srv, ms, admin, _ := setupDatabaseAPITest(t)

	body := `{"name":"nossl","upstream":"h:5432","mount":"database","role":"ro"}`
	rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add without sslmode: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Database databaseServiceView `json:"database"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Database.SSLMode != "prefer" {
		t.Fatalf("expected default sslmode 'prefer', got %q", resp.Database.SSLMode)
	}
	if got, _ := ms.GetDatabaseService(context.Background(), "root-ns-id", "nossl"); got == nil || got.SSLMode != "prefer" {
		t.Fatalf("stored sslmode should be 'prefer', got %+v", got)
	}
}

// TestDatabaseAPIRejectsNegativeMaxConns pins that a negative max_conns is a 400
// (client error), not a 500 from the store's CHECK(max_conns >= 0).
func TestDatabaseAPIRejectsNegativeMaxConns(t *testing.T) {
	srv, _, admin, _ := setupDatabaseAPITest(t)
	body := `{"name":"neg","upstream":"h:5432","mount":"database","role":"ro","max_conns":-1}`
	rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("negative max_conns: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDatabaseAPIValidation(t *testing.T) {
	srv, _, admin, _ := setupDatabaseAPITest(t)

	cases := map[string]string{
		"missing role":     `{"name":"x","upstream":"h:5432","mount":"database"}`,
		"missing mount":    `{"name":"x","upstream":"h:5432","role":"ro"}`,
		"missing upstream": `{"name":"x","mount":"database","role":"ro"}`,
		"bad host:port":    `{"name":"x","upstream":"nohostport","mount":"database","role":"ro"}`,
		"bad sslmode":      `{"name":"x","upstream":"h:5432","mount":"database","role":"ro","sslmode":"bogus"}`,
		"malformed json":   `{`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", admin, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %q, got %d: %s", name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDatabaseAPIRequiresAdminForWrites(t *testing.T) {
	srv, _, _, member := setupDatabaseAPITest(t)

	// A member cannot add.
	rec := doDatabaseRequest(t, srv, http.MethodPost, "/v1/vaults/default/databases", member, validDatabaseBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member add: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// A member cannot delete.
	rec = doDatabaseRequest(t, srv, http.MethodDelete, "/v1/vaults/default/databases/alloy", member, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member delete: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// But a member CAN list (read access).
	rec = doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/default/databases", member, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("member list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestDiscoverIncludesDatabases pins that /discover surfaces the vault's managed
// databases (name + upstream host only, never the Vault mount/role).
func TestDiscoverIncludesDatabases(t *testing.T) {
	ms, token := setupMockStoreWithScopedSessionRole(t, "default", "root-ns-id", "proxy")
	srv := newTestServer(withStore(ms))

	if _, err := ms.UpsertDatabaseService(context.Background(), store.DatabaseService{
		VaultID: "root-ns-id", Name: "analytics", Upstream: "db.internal:5432",
		Mount: "database", Role: "secret-role", SSLMode: "require",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Databases []struct {
			Name string `json:"name"`
			Host string `json:"host"`
		} `json:"databases"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Databases) != 1 || resp.Databases[0].Name != "analytics" || resp.Databases[0].Host != "db.internal:5432" {
		t.Fatalf("unexpected databases in discover: %+v", resp.Databases)
	}
	// The Vault role must never appear in the discovery payload.
	if strings.Contains(rec.Body.String(), "secret-role") {
		t.Fatal("discovery leaked the Vault role")
	}
}

func TestDatabaseAPINotFound(t *testing.T) {
	srv, _, admin, _ := setupDatabaseAPITest(t)

	// Unknown vault.
	rec := doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/nope/databases", admin, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown vault: expected 404, got %d", rec.Code)
	}
	// Unknown database on a real vault.
	rec = doDatabaseRequest(t, srv, http.MethodGet, "/v1/vaults/default/databases/ghost", admin, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown db get: expected 404, got %d", rec.Code)
	}
	// Delete of an unknown database is 404, not a silent success.
	rec = doDatabaseRequest(t, srv, http.MethodDelete, "/v1/vaults/default/databases/ghost", admin, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown db delete: expected 404, got %d", rec.Code)
	}
}

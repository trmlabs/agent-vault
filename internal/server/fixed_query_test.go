package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestFixedQueryOwnerConfiguration(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))
	send := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	good := `{"services":[{"name":"read","host":"api.example.test/v1/search","auth":{"type":"passthrough"},"fixed_query":{"keyword":"synthetic","limit":"1"},"substitutions":[{"key":"API_KEY","placeholder":"__vault_API_KEY__","in":["header"]}]}]}`
	if send(good) != 200 {
		t.Fatal("owner profile rejected")
	}
	saved := ms.brokerConfigs["root-ns-id"].ServicesJSON
	var services []broker.Service
	if json.Unmarshal([]byte(saved), &services) != nil || len(services) != 1 || services[0].FixedQuery["keyword"] != "synthetic" {
		t.Fatal("profile did not survive persistence")
	}
	for _, body := range []string{
		strings.Replace(good, `"keyword":"synthetic"`, `"keyword":"synthetic","keyword":"override"`, 1),
		strings.Replace(good, `"read"`, `"collision"`, 1),
		strings.Replace(good, `/v1/search`, `/v1/*`, 1),
	} {
		if send(body) != 400 || ms.brokerConfigs["root-ns-id"].ServicesJSON != saved {
			t.Fatal("invalid/ambiguous update changed stored configuration")
		}
	}
}

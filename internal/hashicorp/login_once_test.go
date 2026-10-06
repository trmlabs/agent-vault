package hashicorp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestLoginOnceLogsInAndRevokes(t *testing.T) {
	var logins, revokes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/gke-us-saas-staging-gatehouse/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role"] != "gatehouse-litellm-keys" || body["jwt"] != "a.b.c" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "hvs.synthetic", "lease_duration": 300}})
		case "/v1/auth/token/revoke-self":
			if r.Header.Get("X-Vault-Token") == "hvs.synthetic" {
				revokes.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("a.b.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_ADDR", srv.URL)
	env := map[string]string{"VAULT_ADDR": srv.URL, "VAULT_JWT_MOUNT": "gke-us-saas-staging-gatehouse",
		"VAULT_JWT_ROLE": "gatehouse-litellm-keys", "VAULT_JWT_TOKEN_FILE": tokenFile}
	getenv := func(k string) string { return env[k] }

	_, done, err := LoginOnce(context.Background(), getenv)
	if err != nil {
		t.Fatal(err)
	}
	done()
	if logins.Load() != 1 || revokes.Load() != 1 {
		t.Fatalf("logins=%d revokes=%d", logins.Load(), revokes.Load())
	}

	for name, change := range map[string][2]string{
		"no address":    {"VAULT_ADDR", ""},
		"skip verify":   {"VAULT_SKIP_VERIFY", "true"},
		"no role":       {"VAULT_JWT_ROLE", ""},
		"wrong role":    {"VAULT_JWT_ROLE", "someone-else"},
		"missing token": {"VAULT_JWT_TOKEN_FILE", filepath.Join(t.TempDir(), "absent")},
	} {
		saved := env[change[0]]
		env[change[0]] = change[1]
		if _, _, err := LoginOnce(context.Background(), getenv); err == nil {
			t.Errorf("%s: logged in", name)
		}
		env[change[0]] = saved
	}
}

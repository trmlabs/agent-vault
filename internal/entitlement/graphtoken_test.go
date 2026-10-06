package entitlement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTenant = "11111111-1111-1111-1111-111111111111"
	testApp    = "22222222-2222-2222-2222-222222222222"
)

// entra stands in for the token endpoint: it checks the form and answers with
// the configured status and body, counting exchanges.
func entra(t *testing.T, status int, body func(n int64) any) (*httptest.Server, *atomic.Int64, *atomic.Value) {
	t.Helper()
	var calls atomic.Int64
	var lastAssertion atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/"+testTenant+"/oauth2/v2.0/token" || r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != testApp ||
			r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			r.PostForm.Get("scope") != "https://graph.microsoft.com/.default" || r.PostForm.Get("client_secret") != "" {
			w.WriteHeader(400)
			return
		}
		lastAssertion.Store(r.PostForm.Get("client_assertion"))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body(n))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastAssertion
}

func assertionFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFederatedTokenExchangesCachesAndRefreshes(t *testing.T) {
	srv, calls, last := entra(t, 200, func(n int64) any {
		return map[string]any{"access_token": "graph-token-" + string(rune('0'+n)), "token_type": "Bearer", "expires_in": 3599}
	})
	path := assertionFile(t, "sa-token-1\n")
	now := time.Unix(1_800_000_000, 0)
	f := &FederatedToken{TenantID: testTenant, ClientID: testApp, AssertionFile: path, Client: srv.Client(), Login: srv.URL,
		Now: func() time.Time { return now }}

	tok, err := f.Token(context.Background())
	if err != nil || tok != "graph-token-1" || last.Load() != "sa-token-1" {
		t.Fatalf("first: %q %v %v", tok, err, last.Load())
	}
	now = now.Add(50 * time.Minute)
	if tok, _ := f.Token(context.Background()); tok != "graph-token-1" || calls.Load() != 1 {
		t.Fatalf("cached token not reused: %q after %d exchanges", tok, calls.Load())
	}
	// Inside the refresh margin, the kubelet's rotated file is the new assertion.
	_ = os.WriteFile(path, []byte("sa-token-2"), 0o600)
	now = now.Add(6 * time.Minute)
	if tok, err := f.Token(context.Background()); err != nil || tok != "graph-token-2" || last.Load() != "sa-token-2" {
		t.Fatalf("refresh: %q %v %v", tok, err, last.Load())
	}
}

func TestFederatedTokenFailuresNameNoSecret(t *testing.T) {
	const assertion = "sa-token-secret-part"
	cases := map[string]struct {
		status int
		body   any
		file   string
	}{
		"no federated credential": {400, map[string]any{"error": "invalid_client", "error_codes": []int{70021}, "error_description": "echo " + assertion}, assertion},
		"no bearer token":         {200, map[string]any{"access_token": "graph-token", "token_type": "pop", "expires_in": 3599}, assertion},
		"no lifetime":             {200, map[string]any{"access_token": "graph-token", "token_type": "Bearer"}, assertion},
		"empty file":              {200, map[string]any{}, "  \n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _, _ := entra(t, c.status, func(int64) any { return c.body })
			f := &FederatedToken{TenantID: testTenant, ClientID: testApp, AssertionFile: assertionFile(t, c.file), Client: srv.Client(), Login: srv.URL}
			tok, err := f.Token(context.Background())
			if err == nil || tok != "" {
				t.Fatalf("accepted: %q", tok)
			}
			if strings.Contains(err.Error(), assertion) || strings.Contains(err.Error(), "graph-token") {
				t.Fatalf("error carries a secret: %v", err)
			}
		})
	}
	f := &FederatedToken{TenantID: testTenant, ClientID: testApp, AssertionFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := f.Token(context.Background()); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestFederatedTokenExpiresInAsString(t *testing.T) {
	srv, _, _ := entra(t, 200, func(int64) any {
		return map[string]any{"access_token": "graph-token", "token_type": "Bearer", "expires_in": "3599"}
	})
	f := &FederatedToken{TenantID: testTenant, ClientID: testApp, AssertionFile: assertionFile(t, "sa"), Client: srv.Client(), Login: srv.URL}
	if tok, err := f.Token(context.Background()); err != nil || tok != "graph-token" {
		t.Fatalf("%q %v", tok, err)
	}
}

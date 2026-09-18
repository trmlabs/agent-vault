//go:build realvault

package mitm

import (
	"context"
	"html"
	"io"
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
)

func testRealVaultFixedQuery(t *testing.T, hc *hashicorp.Client, admin *vaultapi.Client) {
	f, vaultID := fixedQueryFixture(t, nil)
	ctx := context.Background()
	_, err := f.store.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: vaultID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"fixed-query-reference","kv_version":2}`, PollIntervalSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	f.proxy.creds.(*brokercore.StoreCredentialProvider).RequestSecrets = hashicorp.RequestResolver{Store: f.store, Fetcher: hc}
	expected := ""
	echo := false
	f.upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		f.calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != expected || password != "" || r.URL.RawQuery != "keyword=synthetic+%26+limit%3D999%250d&limit=1" {
			http.Error(w, "unexpected request", 400)
			return
		}
		if echo {
			_, _ = io.WriteString(w, html.EscapeString(r.Header.Get("Authorization")))
			return
		}
		_, _ = io.WriteString(w, `{"found":true}`)
	})
	request := func() int {
		result, _ := f.send(t, "/search", func(r *http.Request) { r.SetBasicAuth("__vault_API_KEY__", "") })
		return result.StatusCode
	}
	for _, value := range []string{"real-vault-synthetic-first", "real-vault-synthetic-rotated"} {
		expected = value
		if _, err := admin.Logical().WriteWithContext(ctx, "secret/data/fixed-query-reference", map[string]interface{}{"data": map[string]interface{}{"API_KEY": value}}); err != nil {
			t.Fatal("fixture write failed")
		}
		before := f.calls.Load()
		if request() != 200 || f.calls.Load() != before+1 {
			t.Fatal("real Vault fixed query freshness failed")
		}
	}
	echo = true
	if request() != 502 {
		t.Fatal("real Vault credential echo escaped")
	}
	echo = false
	before := f.calls.Load()
	f.audit.failBegin.Store(true)
	if request() != 503 || f.calls.Load() != before {
		t.Fatal("audit outage forwarded fixed query")
	}
	f.audit.failBegin.Store(false)
	if _, err := admin.Logical().DeleteWithContext(ctx, "secret/metadata/fixed-query-reference"); err != nil {
		t.Fatal("fixture deletion failed")
	}
	if request() != 403 || f.calls.Load() != before {
		t.Fatal("missing Vault secret used cached value")
	}
}

package mitm

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

type fixedQuerySecrets struct {
	value string
	calls int
}

func (s *fixedQuerySecrets) ReadForRequest(context.Context, string) (map[string]string, bool, error) {
	s.calls++
	if s.value == "" {
		return nil, true, errors.New("unavailable")
	}
	return map[string]string{"API_KEY": s.value}, true, nil
}

func fixedQueryFixture(t *testing.T, secrets brokercore.RequestSecretResolver) (*strictFixture, string) {
	t.Helper()
	f := newStrictFixture(t)
	v, err := f.store.CreateVault(context.Background(), "fixed-query")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	svc := broker.Service{Name: "search", Host: u.Hostname(), Port: &port, Path: "/search", Auth: broker.Auth{Type: "passthrough"}, FixedQuery: broker.FixedQuery{"keyword": "synthetic & limit=999%0d", "limit": "1"}, Substitutions: []broker.Substitution{{Key: "API_KEY", Placeholder: "__vault_API_KEY__", In: []string{"header"}}}}
	data, err := json.Marshal([]broker.Service{svc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetBrokerConfig(context.Background(), v.ID, string(data)); err != nil {
		t.Fatal(err)
	}
	provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{f.store}, make([]byte, 32))
	provider.RequestSecrets = secrets
	f.proxy.creds = provider
	f.proxy.sessions = validTokenResolver("workload-token", &brokercore.ProxyScope{VaultID: v.ID, AgentID: "agent-1", VaultRole: "proxy"})
	return f, v.ID
}

func TestStrictFixedQuery(t *testing.T) {
	secrets := &fixedQuerySecrets{value: strictCanary}
	f, _ := fixedQueryFixture(t, secrets)
	echo := false
	f.upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		f.calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != secrets.value || password != "" || r.Method != "GET" || r.URL.Path != "/search" || r.URL.RawQuery != "keyword=synthetic+%26+limit%3D999%250d&limit=1" || r.Header.Get("Accept-Encoding") != "identity" {
			http.Error(w, "bad request", 400)
			return
		}
		if echo {
			_, _ = io.WriteString(w, html.EscapeString(r.Header.Get("Authorization")))
			return
		}
		_, _ = io.WriteString(w, `{"found":true}`)
	})
	basic := func(r *http.Request) { r.SetBasicAuth("__vault_API_KEY__", "") }
	for _, value := range []string{strictCanary, "rotated-synthetic-value"} {
		secrets.value = value
		before := secrets.calls
		result, body := f.send(t, "/search", basic)
		if result.StatusCode != 200 || body != `{"found":true}` || secrets.calls != before+1 {
			t.Fatal("fixed query positive/freshness control failed")
		}
	}
	for _, tc := range []struct {
		path   string
		mutate func(*http.Request)
	}{
		{"/search?keyword=synthetic", basic}, {"/search?limit=1&limit=2", basic}, {"/search?", basic}, {"/search?x=%0d%0a", basic}, {"/search?x=%26limit%3D99", basic},
		{"/search", func(r *http.Request) { basic(r); r.Method = "HEAD" }},
		{"/search", func(r *http.Request) { basic(r); r.Method = "POST" }},
		{"/search", func(r *http.Request) { basic(r); r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 }},
		{"/other", basic}, {"/%73earch", basic},
	} {
		before := f.calls.Load()
		result, _ := f.send(t, tc.path, tc.mutate)
		if result.StatusCode < 400 || f.calls.Load() != before {
			t.Fatalf("unsupported request forwarded: %s", tc.path)
		}
	}
	echo = true
	result, _ := f.send(t, "/search", basic)
	if result.StatusCode != 502 {
		t.Fatal("encoded credential echo escaped")
	}
	echo = false
	before := f.calls.Load()
	f.audit.failBegin.Store(true)
	result, _ = f.send(t, "/search", basic)
	if result.StatusCode != 503 || f.calls.Load() != before {
		t.Fatal("audit failure forwarded")
	}
	f.audit.failBegin.Store(false)
	secrets.value = ""
	result, _ = f.send(t, "/search", basic)
	if result.StatusCode != 403 || f.calls.Load() != before {
		t.Fatal("unavailable credential forwarded")
	}
}

func TestLegacyRejectsFixedQuery(t *testing.T) {
	f, _ := fixedQueryFixture(t, &fixedQuerySecrets{value: strictCanary})
	f.proxy.strictCredentialProxy = false
	result, _ := f.send(t, "/search", nil)
	if result.StatusCode != 403 || f.calls.Load() != 0 {
		t.Fatal("legacy proxy forwarded restricted service")
	}
}

func TestFixedQueryRequiresExplicitNonDefaultPort(t *testing.T) {
	f, vaultID := fixedQueryFixture(t, &fixedQuerySecrets{value: strictCanary})
	row, err := f.store.GetBrokerConfig(context.Background(), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(row.ServicesJSON), &services); err != nil {
		t.Fatal(err)
	}
	services[0].Host, services[0].Path, _ = broker.SplitInlineHost(services[0].Host, services[0].Path)
	services[0].Port = nil
	encoded, err := json.Marshal(services)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SetBrokerConfig(context.Background(), vaultID, string(encoded)); err != nil {
		t.Fatal(err)
	}
	result, _ := f.send(t, "/search", nil)
	if result.StatusCode != 403 || f.calls.Load() != 0 {
		t.Fatal("unconfigured non-default port forwarded")
	}
}

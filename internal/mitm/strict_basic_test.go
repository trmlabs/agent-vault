package mitm

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type basicFreshCredentials struct {
	value string
	reads int
}

func (c *basicFreshCredentials) Inject(_ context.Context, _, host string, _ int, path string) (*brokercore.InjectResult, error) {
	c.reads++
	if c.value == "" || path == "/unmapped" {
		return nil, errors.New("unavailable")
	}
	return &brokercore.InjectResult{MatchedName: "approved", MatchedHost: host,
		CredentialKeys: []string{"API_KEY"}, Substitutions: []brokercore.ResolvedSubstitution{
			{Placeholder: "__vault_API_KEY__", Value: c.value, In: []string{"header"}},
		}}, nil
}

// Exercise the real CONNECT/TLS forwarding path with a request-scoped resolver
// seam. This verifies wire compatibility, not a deployed Vault integration.
func TestStrictBasicPlaceholder(t *testing.T) {
	f := newStrictFixture(t)
	c := &basicFreshCredentials{value: strictCanary}
	f.proxy.creds = c
	f.upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != c.value || password != "" || r.Header.Get("Proxy-Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/echo-basic":
			io.WriteString(w, r.Header.Get("Authorization"))
		case "/echo-basic-header":
			w.Header().Set("X-Echo", strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
		case "/echo-basic-trailer":
			w.Header().Set("Trailer", "X-Echo")
			w.WriteHeader(200)
			io.WriteString(w, "ok")
			w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		default:
			io.WriteString(w, "approved-output")
		}
	})
	request := func(t *testing.T, path, username, password string) strictResponse {
		t.Helper()
		resp, body := f.send(t, path, func(r *http.Request) { r.SetBasicAuth(username, password) })
		if c.value != "" && strings.Contains(body, base64.StdEncoding.EncodeToString([]byte(c.value+":"))) {
			t.Fatal("encoded Basic credential escaped")
		}
		return resp
	}
	for _, value := range []string{strictCanary, "rotated-synthetic-key-5ef921"} {
		c.value = value
		before := c.reads
		if got := request(t, "/ok", "__vault_API_KEY__", ""); got.StatusCode != 200 || c.reads != before+1 {
			t.Fatalf("fresh Basic request status=%d reads=%d", got.StatusCode, c.reads-before)
		}
	}
	for _, path := range []string{"/echo-basic", "/echo-basic-header", "/echo-basic-trailer"} {
		if got := request(t, path, "__vault_API_KEY__", ""); got.StatusCode != 502 {
			t.Fatalf("echo status=%d", got.StatusCode)
		}
	}
	for _, tc := range []struct{ name, user, password string }{
		{"unknown", "__vault_OTHER__", ""},
		{"literal", "literal-user", ""},
		{"bearer-prefixed", "Bearer __vault_API_KEY__", ""},
		{"password", "__vault_API_KEY__", "password"},
		{"password-marker", "__vault_API_KEY__", "__vault_API_KEY__"},
		{"mixed", "__vault_API_KEY____vault_OTHER__", ""},
		{"malformed", "__vault_API_KEY_", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.calls.Load()
			if got := request(t, "/ok", tc.user, tc.password); got.StatusCode != 400 || f.calls.Load() != before {
				t.Fatalf("invalid Basic status=%d outbound=%d", got.StatusCode, f.calls.Load()-before)
			}
		})
	}
	for _, header := range []string{"Basic !!!", "Basic " + base64.StdEncoding.EncodeToString([]byte("__vault_API_KEY__")), "Basic  " + base64.StdEncoding.EncodeToString([]byte("__vault_API_KEY__:"))} {
		before := f.calls.Load()
		got, _ := f.send(t, "/ok", func(r *http.Request) { r.Header.Set("Authorization", header) })
		if got.StatusCode != 400 || f.calls.Load() != before {
			t.Fatal("malformed Basic forwarded")
		}
	}
	before := f.calls.Load()
	got, _ := f.send(t, "/ok", func(r *http.Request) {
		r.SetBasicAuth("__vault_API_KEY__", "")
		r.Header.Add("Authorization", "Bearer __vault_API_KEY__")
	})
	if got.StatusCode != 400 || f.calls.Load() != before {
		t.Fatal("duplicate authentication forwarded")
	}
	if got := request(t, "/unmapped", "__vault_API_KEY__", ""); got.StatusCode != 403 || f.calls.Load() != before {
		t.Fatal("unmapped destination forwarded")
	}
	f.audit.failBegin.Store(true)
	if got := request(t, "/ok", "__vault_API_KEY__", ""); got.StatusCode != 503 || f.calls.Load() != before {
		t.Fatal("audit failure forwarded")
	}
	f.audit.failBegin.Store(false)
	for _, value := range []string{"", "invalid:username"} {
		c.value = value
		before := f.calls.Load()
		got := request(t, "/ok", "__vault_API_KEY__", "")
		if got.StatusCode < 400 || f.calls.Load() != before {
			t.Fatal("unavailable or invalid credential forwarded")
		}
	}
}

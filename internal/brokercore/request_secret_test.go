package brokercore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

type requestSecretFixture struct {
	values map[string]string
	err    error
	calls  int
}

func (r *requestSecretFixture) ReadForRequest(context.Context, string) (map[string]string, bool, error) {
	r.calls++
	return r.values, true, r.err
}

func TestRequestSecretProviderNeverUsesLocalFallback(t *testing.T) {
	key := make32(17)
	s := newFakeCredStore()
	s.setServices(t, "vault", []broker.Service{{Name: "approved", Host: "api.example.test", Auth: broker.Auth{Type: "passthrough"}, Substitutions: []broker.Substitution{{Key: "KEY", Placeholder: "__vault_KEY__", In: []string{"header"}}}}})
	s.setCred(t, key, "vault", "KEY", "stale-local-canary")
	fresh := &requestSecretFixture{values: map[string]string{"KEY": "fresh-canary"}}
	p := NewStoreCredentialProvider(s, key)
	p.RequestSecrets = fresh
	check := func(want string) {
		t.Helper()
		result, err := p.Inject(context.Background(), "vault", "api.example.test", 443, "/read")
		if err != nil || len(result.Substitutions) != 1 || result.Substitutions[0].Value != want {
			t.Fatal("request-time credential not returned")
		}
	}
	check("fresh-canary")
	fresh.values = map[string]string{"KEY": "rotated-canary"}
	check("rotated-canary")
	for _, kind := range []string{"deleted-field", "empty-field", "vault-outage"} {
		t.Run(kind, func(t *testing.T) {
			fresh.err = nil
			fresh.values = map[string]string{}
			if kind == "empty-field" {
				fresh.values["KEY"] = ""
			}
			if kind == "vault-outage" {
				fresh.err = errors.New("error with fresh-canary")
			}
			result, err := p.Inject(context.Background(), "vault", "api.example.test", 443, "/read")
			if !errors.Is(err, ErrCredentialMissing) {
				t.Fatal("failed fresh lookup did not deny")
			}
			if strings.Contains(err.Error(), "fresh-canary") {
				t.Fatal("error exposed value")
			}
			if result != nil {
				for _, sub := range result.Substitutions {
					if sub.Value != "" {
						t.Fatal("failure returned a secret")
					}
				}
			}
		})
	}
	if s.getCredentialCalls != 0 {
		t.Fatalf("local fallback reads: %d", s.getCredentialCalls)
	}
	if fresh.calls != 5 {
		t.Fatalf("request-time reads: %d", fresh.calls)
	}
	// Configuration lookup must fail before any secret backend read.
	before := fresh.calls
	s.brokerCfgErr = errors.New("store unavailable")
	if _, err := p.Inject(context.Background(), "vault", "api.example.test", 443, "/read"); err == nil {
		t.Fatal("store failure admitted")
	}
	if fresh.calls != before {
		t.Fatal("secret read despite unavailable service configuration")
	}
}

package hashicorp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type requestConfigStore struct {
	row   *store.VaultCredentialStore
	err   error
	reads int
}

func (s *requestConfigStore) GetVaultCredentialStore(context.Context, string) (*store.VaultCredentialStore, error) {
	s.reads++
	return s.row, s.err
}

type requestFetcher struct {
	values   []Secret
	err      error
	reads    int
	deadline bool
}

func (f *requestFetcher) FetchSecrets(ctx context.Context, _ VaultConfig) ([]Secret, error) {
	f.reads++
	deadline, ok := ctx.Deadline()
	f.deadline = ok && time.Until(deadline) <= 5*time.Second
	return f.values, f.err
}
func requestResolverFixture() (*requestConfigStore, *requestFetcher, RequestResolver) {
	s := &requestConfigStore{row: &store.VaultCredentialStore{Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"approved/service","kv_version":2}`}}
	f := &requestFetcher{values: []Secret{{Key: "KEY", Value: "first"}}}
	return s, f, RequestResolver{Store: s, Fetcher: f}
}

func TestRequestResolverFreshValuesAndNoReuse(t *testing.T) {
	s, f, r := requestResolverFixture()
	ctx := context.Background()
	values, handled, err := r.ReadForRequest(ctx, "vault")
	if err != nil || !handled || values["KEY"] != "first" {
		t.Fatal("initial lookup failed")
	}
	values["KEY"] = "caller mutation"
	f.values = []Secret{{Key: "KEY", Value: "rotated"}}
	values, handled, err = r.ReadForRequest(ctx, "vault")
	if err != nil || !handled || values["KEY"] != "rotated" {
		t.Fatal("rotation was not observed")
	}
	f.values = nil
	values, handled, err = r.ReadForRequest(ctx, "vault")
	if err != nil || !handled || len(values) != 0 {
		t.Fatal("removed field reused")
	}
	if s.reads != 3 || f.reads != 3 || !f.deadline {
		t.Fatalf("reads config=%d fetch=%d bounded=%v", s.reads, f.reads, f.deadline)
	}
}

func TestRequestResolverFailureNeverReturnsOldValues(t *testing.T) {
	for _, kind := range []string{"store-error", "store-missing", "wrong-kind", "fetch-error", "duplicate-fields", "invalid-config", "path-traversal", "path-encoding", "path-query", "nil-store", "nil-fetcher"} {
		t.Run(kind, func(t *testing.T) {
			s, f, r := requestResolverFixture()
			if _, _, err := r.ReadForRequest(context.Background(), "vault"); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "store-error":
				s.err = errors.New("error with secret-canary")
			case "store-missing":
				s.row = nil
			case "wrong-kind":
				s.row.Kind = store.CredentialStoreInfisical
			case "fetch-error":
				f.err = errors.New("error with secret-canary")
			case "duplicate-fields":
				f.values = []Secret{{Key: "KEY", Value: "first"}, {Key: "KEY", Value: "second"}}
			case "invalid-config":
				s.row.ConfigJSON = "invalid secret-canary"
			case "path-traversal":
				s.row.ConfigJSON = `{"mount":"secret","secret_path":"../token"}`
			case "path-encoding":
				s.row.ConfigJSON = `{"mount":"secret","secret_path":"%2e%2e/token"}`
			case "path-query":
				s.row.ConfigJSON = `{"mount":"secret","secret_path":"approved?secret-canary"}`
			case "nil-store":
				r.Store = nil
			case "nil-fetcher":
				r.Fetcher = nil
			}
			values, handled, err := r.ReadForRequest(context.Background(), "vault")
			if !handled || !errors.Is(err, ErrRequestSecret) || values != nil {
				t.Fatal("failure returned values or allowed fallback")
			}
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("secret escaped resolver error")
			}
		})
	}
}

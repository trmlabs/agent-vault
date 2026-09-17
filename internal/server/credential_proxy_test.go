package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/store"
)

type cleanupProbe struct {
	calls  int
	ctxErr error
}

func (c *cleanupProbe) Close(ctx context.Context) error { c.calls++; c.ctxErr = ctx.Err(); return nil }

func TestCredentialProxyStartupFailureReleasesCleanupOwner(t *testing.T) {
	for _, mode := range []string{"no-vault-client", "missing-proxy", "proxy-bind"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer()
			s.EnableCredentialProxy()
			closer := &cleanupProbe{}
			s.AttachDatabaseCleanup(closer)
			if mode != "no-vault-client" {
				s.AttachHashicorp(&hashicorp.Client{})
			}
			if mode == "proxy-bind" {
				occupied, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
				s.AttachMITM(mitm.New(occupied.Addr().String(), mitm.Options{}))
				// Any attempt to bind the management listener before the strict proxy
				// would yield a different error and fail this ordering assertion.
				s.httpServer.Addr = "invalid address"
			}
			err := s.Start()
			if err == nil {
				t.Fatal("invalid startup succeeded")
			}
			if mode == "proxy-bind" && !strings.Contains(err.Error(), "listen credential proxy") {
				t.Fatalf("incorrect startup ordering: %v", err)
			}
			if closer.calls != 1 || closer.ctxErr != nil {
				t.Fatalf("cleanup calls %d context %v", closer.calls, closer.ctxErr)
			}
		})
	}
}

func TestCredentialProxyClearsSynchronizedRows(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v, err := st.CreateVault(ctx, "external")
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"mount":"secret","secret_path":"approved","kv_version":2}`
	_, err = st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: cfg, PollIntervalSeconds: 60, Credentials: []store.EncryptedKV{{Key: "KEY", Ciphertext: []byte("old encrypted credential"), Nonce: []byte("nonce")}}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListCredentials(ctx, v.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal("cache fixture missing")
	}
	s := newTestServer(withStore(st))
	s.AttachHashicorp(&hashicorp.Client{})
	if err := s.prepareCredentialProxy(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = st.ListCredentials(ctx, v.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal("legacy startup unexpectedly removed cache")
	}
	s.EnableCredentialProxy()
	if err := s.prepareCredentialProxy(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = st.ListCredentials(ctx, v.ID)
	if err != nil || len(rows) != 0 {
		t.Fatal("strict startup retained cached values")
	}
	mapping, err := st.GetVaultCredentialStore(ctx, v.ID)
	if err != nil || mapping.ConfigJSON != cfg {
		t.Fatal("startup erased mapping metadata")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareCredentialProxy(ctx); err == nil {
		t.Fatal("unavailable store allowed strict startup")
	}
}

type createMetadataStore struct {
	*mockStore
	captured *store.CreateExternalVaultParams
}

func (s *createMetadataStore) CreateExternalVault(_ context.Context, p store.CreateExternalVaultParams) (*store.Vault, error) {
	s.captured = &p
	return &store.Vault{ID: "new-vault", Name: p.Name}, nil
}

func TestCredentialProxyCreateStoresMetadataWithoutFetching(t *testing.T) {
	st := &createMetadataStore{mockStore: newMockStore()}
	s := newTestServer(withStore(st))
	s.EnableCredentialProxy()
	// This deliberately unconfigured client would panic if the create path
	// attempted a secret read. Configuring the mapping must not fetch a value.
	s.AttachHashicorp(&hashicorp.Client{})
	rec := httptest.NewRecorder()
	s.createHashicorpVault(rec, context.Background(), &Actor{ID: "owner", Type: "user"}, vaultCreateRequest{Name: "approved", CredentialStore: &vaultCreateCredentialStoreRequest{Kind: store.CredentialStoreHashicorp, Config: []byte(`{"mount":"secret","secret_path":"approved"}`)}})
	if rec.Code != http.StatusCreated || st.captured == nil {
		t.Fatalf("metadata creation: %d", rec.Code)
	}
	if len(st.captured.Credentials) != 0 || st.captured.ConfigJSON == "" {
		t.Fatal("create supplied credential values or lost mapping")
	}
}

func TestCredentialProxyManualSynchronizationDenied(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{VaultID: "root-ns-id", Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"approved"}`}
	s := newTestServer(withStore(ms))
	s.EnableCredentialProxy()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("manual sync status %d", rec.Code)
	}
}

type failedClearStore struct{ *mockStore }

func (s failedClearStore) ReplaceVaultCredentialsForSync(context.Context, string, string, []store.EncryptedKV) (bool, error) {
	return false, errors.New("storage error")
}
func TestCredentialProxyCacheClearFailureDeniesStartup(t *testing.T) {
	ms := newMockStore()
	ms.credStores["vault"] = &store.VaultCredentialStore{VaultID: "vault", Kind: store.CredentialStoreHashicorp, ConfigJSON: `{}`}
	s := newTestServer(withStore(failedClearStore{ms}))
	s.EnableCredentialProxy()
	s.AttachHashicorp(&hashicorp.Client{})
	if err := s.prepareCredentialProxy(context.Background()); err == nil {
		t.Fatal("failed cache removal accepted")
	}
}

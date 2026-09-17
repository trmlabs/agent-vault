package server

import (
	"context"
	"fmt"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// EnableCredentialProxy selects request-time Vault reads instead of local
// synchronization. Call once before attaching listeners or starting the server.
func (s *Server) EnableCredentialProxy()       { s.credentialProxy = true }
func (s *Server) CredentialProxyEnabled() bool { return s.credentialProxy }

type requestSecrets struct{ s *Server }

func (r requestSecrets) ReadForRequest(ctx context.Context, id string) (map[string]string, bool, error) {
	if !r.s.credentialProxy {
		return nil, false, nil
	}
	if r.s.hashicorpClient == nil {
		return nil, true, hashicorp.ErrRequestSecret
	}
	return (hashicorp.RequestResolver{Store: r.s.store, Fetcher: r.s.hashicorpClient}).ReadForRequest(ctx, id)
}

// Clear legacy synchronized rows before any listener is started. This prevents
// future use, not forensic erasure of prior database files or backups.
func (s *Server) prepareCredentialProxy(ctx context.Context) error {
	if !s.credentialProxy {
		return nil
	}
	if s.hashicorpClient == nil {
		return fmt.Errorf("credential proxy requires HashiCorp Vault")
	}
	rows, err := s.store.ListVaultCredentialStores(ctx)
	if err != nil {
		return fmt.Errorf("credential proxy cannot inspect cached credentials")
	}
	for _, row := range rows {
		if row.Kind != store.CredentialStoreHashicorp {
			continue
		}
		applied, err := s.store.ReplaceVaultCredentialsForSync(ctx, row.VaultID, row.ConfigJSON, nil)
		if err != nil || !applied {
			return fmt.Errorf("credential proxy cannot clear cached credentials")
		}
	}
	return nil
}

// AttachDatabaseCleanup binds the durable journal owner to server shutdown.
func (s *Server) AttachDatabaseCleanup(c interface{ Close(context.Context) error }) {
	s.pgLeaseCloser = c
}

// CleanupStore supplies the configured persistent store for database journaling.
func (s *Server) CleanupStore() Store { return s.store }

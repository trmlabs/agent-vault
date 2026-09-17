package hashicorp

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// RequestResolver deliberately has no cache or persistence writer. Values live
// only in the calling request and are never taken from the local secret store.
type RequestResolver struct {
	Store interface {
		GetVaultCredentialStore(context.Context, string) (*store.VaultCredentialStore, error)
	}
	Fetcher interface {
		FetchSecrets(context.Context, VaultConfig) ([]Secret, error)
	}
}

var ErrRequestSecret = errors.New("request-time Vault resolution failed")

func (r RequestResolver) ReadForRequest(ctx context.Context, vaultID string) (map[string]string, bool, error) {
	if r.Store == nil || r.Fetcher == nil {
		return nil, true, ErrRequestSecret
	}
	cs, err := r.Store.GetVaultCredentialStore(ctx, vaultID)
	if err != nil || cs == nil || cs.Kind != store.CredentialStoreHashicorp {
		return nil, true, ErrRequestSecret
	}
	cfg, err := ParseConfigJSON(cs.ConfigJSON)
	if err != nil || cfg.Validate() != nil || !safeRequestPath(cfg.Mount) || !safeRequestPath(cfg.SecretPath) {
		return nil, true, ErrRequestSecret
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	secrets, err := r.Fetcher.FetchSecrets(ctx, cfg)
	if err != nil {
		return nil, true, ErrRequestSecret
	}
	values := make(map[string]string, len(secrets))
	for _, s := range secrets {
		if _, exists := values[s.Key]; exists {
			return nil, true, ErrRequestSecret
		}
		values[s.Key] = s.Value
	}
	return values, true, nil
}

func safeRequestPath(p string) bool {
	if p == "" || strings.ContainsAny(p, "?%#\\\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

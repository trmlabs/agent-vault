package hashicorp

import (
	"context"
	"fmt"
	"os"
	"strconv"

	vaultapi "github.com/hashicorp/vault/api"
)

// LoginOnce logs in once with the projected service-account token named by
// VAULT_JWT_MOUNT, VAULT_JWT_ROLE and VAULT_JWT_TOKEN_FILE, for a short job
// that needs no refresh loop. done revokes the login; call it when the job
// ends.
func LoginOnce(ctx context.Context, getenv func(string) string) (logical *vaultapi.Logical, done func(), err error) {
	if getenv("VAULT_ADDR") == "" {
		return nil, nil, ErrNotConfigured
	}
	if skip, _ := strconv.ParseBool(getenv("VAULT_SKIP_VERIFY")); skip {
		return nil, nil, fmt.Errorf("VAULT_SKIP_VERIFY is refused for a job that writes keys")
	}
	c, err := jwtConfigFromEnv(getenv)
	if err != nil {
		return nil, nil, err
	}
	jwt, err := readJWT(c.tokenFile)
	if err != nil {
		return nil, nil, err
	}
	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, nil, fmt.Errorf("hashicorp config: %w", cfg.Error)
	}
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("hashicorp client: %w", err)
	}
	if ns := os.Getenv("VAULT_NAMESPACE"); ns != "" {
		api.SetNamespace(ns)
	}
	api.ClearToken()
	secret, err := api.Logical().WriteWithContext(ctx, "auth/"+c.mount+"/login", map[string]interface{}{"role": c.role, "jwt": jwt})
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, nil, fmt.Errorf("vault jwt login failed")
	}
	api.SetToken(secret.Auth.ClientToken)
	return api.Logical(), func() { revokeToken(api, secret.Auth.ClientToken) }, nil
}

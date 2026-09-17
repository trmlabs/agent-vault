package hashicorp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// DatabaseSession retains its child token only in memory. Persist Accessor before
// ReadCredential. Revocation requests cleanup without touching other sessions;
// an unknown issuance still requires database evidence before reopening access.
type DatabaseSession struct {
	Accessor    string
	ExpiresAt   time.Time
	client      *Client
	mount, role string
}

// DatabaseCredentialPolicyName names the pre-provisioned policy granting only
// read on the selected mount/creds/role. The broker never writes Vault policies.
func DatabaseCredentialPolicyName(mount, role string) string {
	path := strings.Trim(strings.TrimSpace(mount), "/") + "/creds/" + strings.TrimSpace(role)
	return fmt.Sprintf("agent-vault-db-%x", sha256.Sum256([]byte(path)))
}

func (c *Client) NewDatabaseSession(ctx context.Context, mount, role string, ttl time.Duration) (*DatabaseSession, error) {
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return nil, err
	}
	if ttl < time.Second || ttl > 24*time.Hour {
		return nil, fmt.Errorf("database child token TTL must be between one second and 24 hours")
	}
	api, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("prepare database session failed")
	}
	api.SetToken(c.api.Token())
	api.SetMaxRetries(0)
	renewable := false
	started := time.Now()
	secret, err := api.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies:        []string{DatabaseCredentialPolicyName(mount, role)},
		NoDefaultPolicy: true, Renewable: &renewable, Type: "service",
		TTL: ttl.String(), ExplicitMaxTTL: ttl.String(), DisplayName: "agent-vault-database-session",
	})
	if err != nil {
		return nil, fmt.Errorf("create database session failed")
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" || secret.Auth.Accessor == "" || secret.Auth.LeaseDuration <= 0 {
		return nil, fmt.Errorf("database session response missing token, accessor or positive TTL")
	}
	if len(secret.Auth.Policies) != 1 || secret.Auth.Policies[0] != DatabaseCredentialPolicyName(mount, role) || len(secret.Auth.IdentityPolicies) != 0 || secret.Auth.Renewable {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = c.RevokeDatabaseSession(cleanupCtx, secret.Auth.Accessor)
		return nil, fmt.Errorf("database child token has unexpected policy or renewal authority")
	}
	api.SetToken(secret.Auth.ClientToken)
	granted := ttl
	if int64(secret.Auth.LeaseDuration) < int64(ttl/time.Second) {
		granted = time.Duration(secret.Auth.LeaseDuration) * time.Second
	}
	return &DatabaseSession{Accessor: secret.Auth.Accessor, ExpiresAt: started.Add(granted),
		client: &Client{api: api, method: c.method, logger: c.logger}, mount: mount, role: role}, nil
}

func (s *DatabaseSession) ReadCredential(ctx context.Context) (*DatabaseCredential, error) {
	if !time.Now().Before(s.ExpiresAt) {
		return nil, fmt.Errorf("database session expired")
	}
	credential, err := s.client.ReadDatabaseCredential(ctx, s.mount, s.role)
	if err != nil {
		return nil, fmt.Errorf("database credential issuance failed")
	}
	return credential, nil
}

func (c *Client) RevokeDatabaseSession(ctx context.Context, accessor string) error {
	if accessor == "" {
		return fmt.Errorf("database session accessor is required")
	}
	err := c.api.Auth().Token().RevokeAccessorWithContext(ctx, accessor)
	// Retrying after a successful revoke and failed journal deletion is safe.
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid accessor" {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revoke database session failed")
	}
	return nil
}

// RevokeDatabaseLeaseConfirmed refuses to treat a queued revoke as cleanup.
// The path form lets policy scope revocation to the integration's lease prefix.
func (c *Client) RevokeDatabaseLeaseConfirmed(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("database lease ID is required")
	}
	for _, part := range strings.Split(leaseID, "/") {
		if !databasePathSegment.MatchString(part) {
			return fmt.Errorf("invalid database lease ID")
		}
	}
	if _, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/revoke/"+leaseID, map[string]interface{}{"sync": true}); err != nil {
		return fmt.Errorf("synchronous database revoke failed")
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/lookup", map[string]interface{}{"lease_id": leaseID})
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid lease" {
		return nil
	}
	if err != nil {
		return fmt.Errorf("confirm database lease removal failed")
	}
	if secret == nil {
		return fmt.Errorf("database lease lookup returned no confirmation")
	}
	return fmt.Errorf("database lease still present after revoke")
}

package hashicorp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	client      *Client // holds the child token
	parent      *Client
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
	session, denied, err := c.newDatabaseSession(ctx, mount, role, ttl)
	if denied == "" || c.logins == nil {
		return session, err
	}
	// Vault refused the child policy to this login. If the catalog added the
	// database after the login was issued, a new login holds it: log in
	// again once and retry once. A policy a new login also lacked is missing,
	// not new: it waits for the next scheduled login instead of minting
	// logins that would each live out their maximum lifetime.
	policy := DatabaseCredentialPolicyName(mount, role)
	if c.policyMissing(policy) {
		return nil, errSessionPolicy
	}
	if err := c.reloginAfterDenial(ctx, denied); err != nil {
		c.logger.Warn("database session refused: the broker's vault login lacks its policy", slog.String("reason", err.Error()))
		return nil, errSessionPolicy
	}
	if session, denied, err = c.newDatabaseSession(ctx, mount, role, ttl); denied != "" {
		c.markPolicyMissing(policy)
		c.logger.Warn("database session refused: a new vault login also lacks its policy; no more logins for it until the next scheduled one")
		return nil, errSessionPolicy
	}
	return session, err
}

var errSessionPolicy = errors.New("create database session failed: vault login lacks this database's policy")

// newDatabaseSession mints one child token. denied is the parent login's
// token when Vault answered 403, the login lacking the child policy.
func (c *Client) newDatabaseSession(ctx context.Context, mount, role string, ttl time.Duration) (session *DatabaseSession, denied string, err error) {
	api, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, "", fmt.Errorf("prepare database session failed")
	}
	parent, ceiling, done := c.api.Token(), time.Time{}, func(string, time.Time) {}
	if c.logins != nil {
		// Only a young login may parent a new session; see reauth.go.
		if parent, ceiling, done, err = c.logins.acquire(c.clock()); err != nil {
			return nil, "", err
		}
	}
	accessor, expiry := "", time.Time{}
	defer func() { done(accessor, expiry) }()
	api.SetToken(parent)
	api.SetMaxRetries(0)
	renewable := false
	started := c.clock()
	secret, err := api.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies:        []string{DatabaseCredentialPolicyName(mount, role)},
		NoDefaultPolicy: true, Renewable: &renewable, Type: "service",
		TTL: ttl.String(), ExplicitMaxTTL: ttl.String(), DisplayName: "agent-vault-database-session",
	})
	var refused *vaultapi.ResponseError
	if errors.As(err, &refused) && refused.StatusCode == http.StatusForbidden {
		return nil, parent, fmt.Errorf("create database session failed")
	}
	if err != nil {
		return nil, "", fmt.Errorf("create database session failed")
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" || secret.Auth.Accessor == "" || secret.Auth.LeaseDuration <= 0 {
		return nil, "", fmt.Errorf("database session response missing token, accessor or positive TTL")
	}
	if len(secret.Auth.Policies) != 1 || secret.Auth.Policies[0] != DatabaseCredentialPolicyName(mount, role) || len(secret.Auth.IdentityPolicies) != 0 || secret.Auth.Renewable {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		api.SetToken(secret.Auth.ClientToken)
		_ = api.Auth().Token().RevokeSelfWithContext(cleanupCtx, "")
		if c.logins != nil {
			c.logins.forget(secret.Auth.Accessor)
		}
		return nil, "", fmt.Errorf("database child token has unexpected policy or renewal authority")
	}
	api.SetToken(secret.Auth.ClientToken)
	granted := ttl
	if int64(secret.Auth.LeaseDuration) < int64(ttl/time.Second) {
		granted = time.Duration(secret.Auth.LeaseDuration) * time.Second
	}
	accessor, expiry = secret.Auth.Accessor, started.Add(granted)
	if !ceiling.IsZero() && ceiling.Before(expiry) {
		expiry = ceiling
	}
	return &DatabaseSession{Accessor: accessor, ExpiresAt: expiry,
		client: &Client{api: api, method: c.method, logger: c.logger, now: c.now}, parent: c, mount: mount, role: role}, "", nil
}

// Revoke ends the session with its own child token (auth/token/revoke-self),
// which revokes the leases it issued with it. Only this process ever held the
// token, so the broker needs no right over any other token. If it fails, the
// token stays harmless: its value lives only in this process, its leases are
// revoked by path, and it expires within its TTL, or sooner with its parent
// login, which no longer waits for it.
func (s *DatabaseSession) Revoke(ctx context.Context) error {
	err := s.client.api.Auth().Token().RevokeSelfWithContext(ctx, "")
	if s.parent != nil && s.parent.logins != nil {
		s.parent.logins.forget(s.Accessor)
		s.parent.revokeIdle(ctx)
	}
	if err != nil {
		return fmt.Errorf("revoke database session failed")
	}
	return nil
}

func (s *DatabaseSession) ReadCredential(ctx context.Context) (*DatabaseCredential, error) {
	if !s.client.clock().Before(s.ExpiresAt) {
		return nil, fmt.Errorf("database session expired")
	}
	credential, err := s.client.ReadDatabaseCredential(ctx, s.mount, s.role)
	if err != nil {
		return nil, fmt.Errorf("database credential issuance failed")
	}
	return credential, nil
}

// RevokeDatabaseSession revokes a child token by accessor. The broker's own
// cleanup no longer uses it: a held session revokes itself, and a dead
// replica's tokens expire within their TTL after their leases are revoked by
// path. It remains for operators with revoke-accessor. A policy without that
// right refuses it (403), which counts as done.
func (c *Client) RevokeDatabaseSession(ctx context.Context, accessor string) error {
	if accessor == "" {
		return fmt.Errorf("database session accessor is required")
	}
	err := c.api.Auth().Token().RevokeAccessorWithContext(ctx, accessor)
	// Retrying after a successful revoke and failed journal deletion is safe.
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid accessor" {
		err = nil
	}
	if errors.As(err, &response) && response.StatusCode == 403 {
		if c.logger != nil {
			c.logger.Info("vault refused accessor revoke; the database session token expires at its TTL")
		}
		err = nil
	}
	if err != nil {
		return fmt.Errorf("revoke database session failed")
	}
	if c.logins != nil {
		c.logins.forget(accessor)
		c.revokeIdle(ctx)
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

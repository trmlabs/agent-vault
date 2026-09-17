package hashicorp

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// DatabaseCredential is a dynamic database login minted by Vault's database
// secrets engine (GET <mount>/creds/<role>). Each read returns a distinct,
// short-lived Username/Password bound to its own LeaseID. The credential is
// SECRET: never log the password. The broker may log LeaseID as an audit join key.
type DatabaseCredential struct {
	LeaseID       string
	Username      string
	Password      string
	LeaseDuration time.Duration
	Renewable     bool
}

// ExpiresAt returns the credential's wall-clock expiry given when it was issued.
// The database engine returns a relative TTL, not an absolute time, so the
// caller anchors it conservatively to the start of the read request.
func (d DatabaseCredential) ExpiresAt(issuedAt time.Time) time.Time {
	return issuedAt.Add(d.LeaseDuration)
}

var databasePathSegment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

// ValidateDatabaseReference prevents path traversal and URL metacharacters from
// turning a database-role lookup into a different Vault API operation.
func ValidateDatabaseReference(mount, role string) error {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	role = strings.TrimSpace(role)
	if !databasePathSegment.MatchString(role) {
		return fmt.Errorf("invalid Vault database role")
	}
	for _, segment := range strings.Split(mount, "/") {
		if !databasePathSegment.MatchString(segment) {
			return fmt.Errorf("invalid Vault database mount")
		}
	}
	return nil
}

// ReadDatabaseCredential mints a fresh dynamic credential for a database role.
// mount is the database secrets-engine mount (e.g. "database"); role is a Vault
// role that maps to a set of SQL privileges. Every call yields a distinct
// username/password on its own lease, so one agent connection never reuses
// another's credential. The call is context-aware; cancellation propagates.
func (c *Client) ReadDatabaseCredential(ctx context.Context, mount, role string) (*DatabaseCredential, error) {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	role = strings.TrimSpace(role)
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/creds/%s", mount, role)
	// GET on this endpoint creates a role. Retrying an ambiguous response can
	// create extra credentials whose lease IDs we never receive. Clone per call
	// so concurrent KV reads retain their retry policy and token rotation is seen.
	mintAPI, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("prepare credential request: %w", err)
	}
	mintAPI.SetToken(c.api.Token())
	mintAPI.SetMaxRetries(0)
	secret, err := mintAPI.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no credential at %s (is the database role configured?)", path)
	}
	username := stringValue(secret.Data["username"])
	password := stringValue(secret.Data["password"])
	if username == "" || password == "" || secret.LeaseID == "" || secret.LeaseDuration <= 0 || int64(secret.LeaseDuration) > math.MaxInt64/int64(time.Second) {
		// Even an unusable response can represent a live minted role.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()
		if err := c.RevokeLease(cleanupCtx, secret.LeaseID); err != nil {
			return nil, fmt.Errorf("invalid database credential; cleanup failed: %w", err)
		}
		return nil, fmt.Errorf("credential at %s is missing username or password, lease ID, or a positive TTL", path)
	}
	return &DatabaseCredential{
		LeaseID:       secret.LeaseID,
		Username:      username,
		Password:      password,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		Renewable:     secret.Renewable,
	}, nil
}

// RenewLease extends a lease by increment (a hint Vault may clamp to the role's
// max TTL) and returns the granted duration. Renewal keeps the same
// username/password valid, so a database session that outlives its original TTL
// is not interrupted. A non-renewable or already-expired lease returns an error.
func (c *Client) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, error) {
	if leaseID == "" {
		return 0, fmt.Errorf("lease_id is required")
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/renew", map[string]interface{}{
		"lease_id":  leaseID,
		"increment": int(math.Ceil(increment.Seconds())),
	})
	if err != nil {
		return 0, fmt.Errorf("renew lease: %w", err)
	}
	if secret == nil || secret.LeaseDuration <= 0 || int64(secret.LeaseDuration) > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("renew lease: missing positive TTL")
	}
	return time.Duration(secret.LeaseDuration) * time.Second, nil
}

// RevokeLease revokes a lease, immediately invalidating its credential — the
// database engine drops the generated user. This is the kill switch: a
// disconnected or compromised session's credential stops working at once rather
// than lingering until its TTL. An empty leaseID is a no-op (nothing was
// minted). A revoke that Vault rejects returns an error; callers on the
// shutdown/cleanup path log it and rely on the lease's max TTL as the backstop.
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	if _, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/revoke", map[string]interface{}{
		"lease_id": leaseID,
	}); err != nil {
		return fmt.Errorf("revoke lease: %w", err)
	}
	return nil
}

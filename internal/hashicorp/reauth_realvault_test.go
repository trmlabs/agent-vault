//go:build realvault

package hashicorp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// TestRealVault_JWTLoginRefresh runs against a disposable dev Vault (root
// VAULT_TOKEN). It checks the token-tree behavior the fake assumes: a session
// is capped by its parent login's fixed maximum, survives a refresh, and the
// older login is revoked when that session ends.
func TestRealVault_JWTLoginRefresh(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("requires a disposable dev Vault")
	}
	ctx := context.Background()
	root, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	mount := fmt.Sprintf("jwt-reauth-%d", time.Now().UnixNano())
	child := DatabaseCredentialPolicyName("database", "reader")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(root.Sys().EnableAuthWithOptionsWithContext(ctx, mount, &vaultapi.EnableAuthOptions{Type: "jwt"}))
	t.Cleanup(func() { _ = root.Sys().DisableAuthWithContext(context.Background(), mount) })
	must(root.Sys().PutPolicyWithContext(ctx, child, `path "database/creds/reader" { capabilities = ["read"] }`))
	must(root.Sys().PutPolicyWithContext(ctx, "reauth-broker", `
path "auth/token/create" { capabilities = ["update"] }
path "auth/token/revoke-accessor" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }`))
	_, err = root.Logical().WriteWithContext(ctx, "auth/"+mount+"/config", map[string]interface{}{
		"jwt_validation_pubkeys": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))},
		"bound_issuer":           "https://issuer.test",
	})
	must(err)
	_, err = root.Logical().WriteWithContext(ctx, "auth/"+mount+"/role/broker", map[string]interface{}{
		"role_type": "jwt", "bound_audiences": []string{"broker"}, "user_claim": "sub",
		"token_policies": []string{"reauth-broker", child}, "token_no_default_policy": true,
		"token_ttl": 6, "token_max_ttl": 12, "token_explicit_max_ttl": 12, "token_type": "service",
	})
	must(err)

	jwtFile := filepath.Join(t.TempDir(), "token")
	sign := func() {
		now := time.Now().Unix()
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{"iss": "https://issuer.test", "aud": "broker", "sub": "system:serviceaccount:gatehouse:broker", "iat": now, "nbf": now - 5, "exp": now + 600})
		input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		must(err)
		must(os.WriteFile(jwtFile, []byte(input+"."+base64.RawURLEncoding.EncodeToString(sig)), 0o600))
	}
	sign()

	api, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	must(err)
	api.ClearToken()
	env := map[string]string{"VAULT_JWT_MOUNT": mount, "VAULT_JWT_ROLE": "broker", "VAULT_JWT_TOKEN_FILE": jwtFile}
	opts := reauthOptions{interval: 3 * time.Second, minSessionLifetime: 4 * time.Second, mintGrace: time.Second, tick: time.Hour}
	c, err := newJWTClient(ctx, api, slog.New(slog.DiscardHandler), func(k string) string { return env[k] }, opts, time.Now)
	must(err)
	defer c.Close()
	first := c.logins.current

	// Request more than the parent has left: Vault caps the session.
	s1, err := c.NewDatabaseSession(ctx, "database", "reader", time.Hour)
	must(err)
	if s1.ExpiresAt.After(first.hardExpiry.Add(time.Second)) {
		t.Fatalf("session outlives its parent login: %v > %v", s1.ExpiresAt, first.hardExpiry)
	}
	alive := func(accessor string) bool {
		_, err := root.Auth().Token().LookupAccessorWithContext(ctx, accessor)
		return err == nil
	}
	firstSelf, err := tokenAPI(root, first.token)
	must(err)
	firstAccessor, err := firstSelf.Auth().Token().LookupSelfWithContext(ctx)
	must(err)
	parentAccessor, _ := firstAccessor.TokenAccessor()

	time.Sleep(3 * time.Second)
	sign()
	c.reauthTick(ctx)
	if c.logins.current == first {
		t.Fatal("login was not refreshed")
	}
	if !alive(s1.Accessor) || !alive(parentAccessor) {
		t.Fatal("refresh ended the live session or its parent")
	}
	s2, err := c.NewDatabaseSession(ctx, "database", "reader", time.Hour)
	must(err)
	must(c.RevokeDatabaseSession(ctx, s1.Accessor))
	if alive(parentAccessor) {
		t.Fatal("older login survived its last session")
	}
	if !alive(s2.Accessor) {
		t.Fatal("revoking the older login ended a session under the new one")
	}
	// Without further refresh, the current login reaches its fixed maximum
	// and Vault ends the session with it, at the ceiling the broker reported.
	time.Sleep(time.Until(s2.ExpiresAt) + 2*time.Second)
	if alive(s2.Accessor) {
		t.Fatal("session outlived its parent login's fixed maximum")
	}
}

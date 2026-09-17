//go:build realvault

package mitm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
)

// Run through examples/postgres-broker/verify.sh against disposable services.
// Synthetic caller identity isolates broker Vault authentication expiry.
func TestRealVault_BrokerParentExpiry(t *testing.T) {
	if os.Getenv("AV_TEST_PG_ADMIN") == "" {
		t.Fatal("requires disposable PostgreSQL/Vault runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	check := func(err error, action string) {
		t.Helper()
		if err != nil {
			t.Fatal(action)
		}
	}
	admin, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	check(err, "Vault client")
	admin.SetToken(os.Getenv("VAULT_TOKEN"))
	role, err := admin.Logical().ReadWithContext(ctx, "database/roles/readonly")
	check(err, "read role")
	if role == nil {
		t.Fatal("missing role")
	}
	saved := role.Data
	extended := make(map[string]interface{}, len(saved))
	for k, v := range saved {
		extended[k] = v
	}
	extended["default_ttl"] = "60s"
	_, err = admin.Logical().WriteWithContext(ctx, "database/roles/readonly", extended)
	check(err, "extend role TTL")
	t.Cleanup(func() {
		_, _ = admin.Logical().WriteWithContext(context.Background(), "database/roles/readonly", saved)
	})
	_, err = admin.Logical().WriteWithContext(ctx, "secret/data/parent-expiry", map[string]interface{}{"data": map[string]interface{}{"API_KEY": "fixture-parent-expiry-key"}})
	check(err, "write KV")
	check(admin.Sys().PutPolicyWithContext(ctx, "parent-expiry", `path "secret/data/parent-expiry" { capabilities = ["read"] }`), "write policy")
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	check(err, "open store")
	defer func() { _ = st.Close() }()
	v, err := st.CreateVault(ctx, "expiry")
	check(err, "create vault")
	_, err = st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"parent-expiry","kv_version":2}`, PollIntervalSeconds: 60})
	check(err, "configure Vault")
	var calls atomic.Int32
	dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-parent-expiry-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "approved")
	}))
	defer dest.Close()
	u, _ := url.Parse(dest.URL)
	port, _ := strconv.Atoi(u.Port())
	services, _ := json.Marshal([]broker.Service{{Name: "read", Host: u.Hostname(), Port: &port, Path: "/approved", Auth: broker.Auth{Type: "passthrough"}, Substitutions: []broker.Substitution{{Key: "API_KEY", Placeholder: "__vault_API_KEY__", In: []string{"header"}}}}})
	_, err = st.SetBrokerConfig(ctx, v.ID, string(services))
	check(err, "service config")
	db, err := pgx.Connect(ctx, os.Getenv("AV_TEST_PG_ADMIN"))
	check(err, "admin DB")
	defer func() { _ = db.Close(context.Background()) }()
	fresh := func(ttl string) (*hashicorp.Client, string) {
		t.Helper()
		token, e := admin.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{Policies: []string{"parent-expiry", "agent-vault-database-parent", hashicorp.DatabaseCredentialPolicyName("database", "readonly")}, TTL: ttl, ExplicitMaxTTL: ttl, Renewable: func() *bool { b := false; return &b }()})
		check(e, "create parent")
		t.Cleanup(func() { _ = admin.Auth().Token().RevokeAccessor(token.Auth.Accessor) })
		t.Setenv("VAULT_TOKEN", token.Auth.ClientToken)
		t.Setenv("VAULT_ROLE_ID", "")
		t.Setenv("VAULT_SECRET_ID", "")
		hc, e := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
		check(e, "broker Vault login")
		return hc, token.Auth.Accessor
	}
	hc, accessor := fresh("8s")
	provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, make([]byte, 32))
	provider.RequestSecrets = hashicorp.RequestResolver{Store: st, Fetcher: hc}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("proof", &brokercore.ProxyScope{VaultID: v.ID, AgentID: "fixture-actor", VaultRole: "proxy"}), provider, func(o *Options) { o.StrictCredentialProxy = true; o.DurableAudit = requestlog.NewDurable(st) })
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(dest.Certificate())
	p.upstream.TLSClientConfig.RootCAs = upstreamRoots
	client := newTrustingClient(proxyURL, url.User("proof"), roots)
	defer client.CloseIdleConnections()
	request := func(want int) {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL+"/approved", nil)
		check(e, "request")
		req.Header.Set("Authorization", "Bearer __vault_API_KEY__")
		resp, e := client.Do(req)
		check(e, "HTTP request")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != want {
			t.Fatalf("HTTP status=%d want=%d", resp.StatusCode, want)
		}
	}
	request(http.StatusOK)
	if calls.Load() != 1 {
		t.Fatal("positive HTTP did not reach destination exactly once")
	}
	m, err := pgproxy.NewDurableLeaseMinter(ctx, hc, st, pgproxy.DurableLeaseOptions{})
	check(err, "minter")
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = m.Close(c)
	}()
	svc := &pgproxy.DatabaseService{Name: "read", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: "appdb", Mount: "database", Role: "readonly", SSLMode: "disable"}
	lease, err := m.Mint(ctx, v.ID, svc)
	check(err, "positive PG issuance")
	cfg, err := pgx.ParseConfig("postgres://" + svc.Addr + "/appdb?sslmode=disable")
	check(err, "PG config")
	cfg.User = lease.Username
	cfg.Password = lease.Password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	check(err, "positive PG authentication")
	defer func() { _ = conn.Close(context.Background()) }()
	queryDone := make(chan error, 1)
	go func() { _, e := conn.Exec(ctx, "SELECT pg_sleep(60)"); queryDone <- e }()
	wait := func(what string, predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if predicate() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal(what)
	}
	wait("query did not start", func() bool {
		var n int
		return db.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND state='active' AND query LIKE 'SELECT pg_sleep%'", lease.Username).Scan(&n) == nil && n == 1
	})
	wait("parent accessor did not expire", func() bool {
		_, e := admin.Auth().Token().LookupAccessorWithContext(ctx, accessor)
		if e == nil {
			return false
		}
		ve, ok := e.(*vaultapi.ResponseError)
		return ok && ve.StatusCode == http.StatusBadRequest
	})
	before := calls.Load()
	request(http.StatusForbidden)
	if calls.Load() != before {
		t.Fatal("expired parent forwarded HTTP")
	}
	if _, e := m.Mint(ctx, v.ID, svc); e == nil {
		t.Fatal("expired parent minted credentials")
	}
	wait("parent expiry did not remove exact role and sessions", func() bool {
		var n int
		return db.QueryRow(ctx, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1)+(SELECT count(*) FROM pg_stat_activity WHERE usename=$1)", lease.Username).Scan(&n) == nil && n == 0
	})
	select {
	case e := <-queryDone:
		if e == nil {
			t.Fatal("running query survived parent expiry")
		}
	case <-ctx.Done():
		t.Fatal("query did not terminate")
	}
	_ = m.Close(ctx)
	pending, err := st.ListDatabaseCleanup(ctx)
	check(err, "read retained cleanup journal")
	if len(pending) != 1 {
		t.Fatal("expired authorization lost pending cleanup evidence")
	}
	hc, _ = fresh("2m")
	provider.RequestSecrets = hashicorp.RequestResolver{Store: st, Fetcher: hc}
	m, err = pgproxy.NewDurableLeaseMinter(ctx, hc, st, pgproxy.DurableLeaseOptions{})
	check(err, "fresh-parent recovery")
	request(http.StatusOK)
	recovered, err := m.Mint(ctx, v.ID, svc)
	check(err, "recovered PG issuance")
	cfg.User = recovered.Username
	cfg.Password = recovered.Password
	recoveredConn, err := pgx.ConnectConfig(ctx, cfg)
	check(err, "recovered PG authentication")
	_, err = recoveredConn.Exec(ctx, "SELECT 1")
	check(err, "recovered query")
	_ = recoveredConn.Close(ctx)
	check(m.Revoke(ctx, recovered.ID), "recovered lease cleanup")
	pending, err = st.ListDatabaseCleanup(ctx)
	check(err, "read reconciled cleanup journal")
	if len(pending) != 0 {
		t.Fatal("fresh parent failed to reconcile cleanup journal")
	}
	t.Log("Observed parent expiry, denied HTTP without destination access, denied new PG issuance, removed running query and role, recovered with fresh parent authentication; synthetic caller identity.")
}

//go:build realcombined

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
)

func TestRealCombinedParentExpiryRecovery(t *testing.T) {
	if os.Getenv("AV_COMBINED_POD_IP") != "" {
		t.Skip("broker lifecycle recovery uses the separate local-client combined runner")
	}
	runCombinedServices(t, true)
}

type combinedRecovery struct {
	ctx                                    context.Context
	store                                  *store.SQLStore
	storePath                              string
	identityConfig                         workloadidentity.Config
	vaultAdmin                             *vaultapi.Client
	accessor, policy, role, proof, vaultID string
	proxy                                  *Proxy
	pg                                     *pgproxy.Broker
	minter                                 *pgproxy.DurableLeaseMinter
	dbAdmin                                *pgx.Conn
	queryDone                              <-chan error
	destination                            *httptest.Server
	request                                func(string, bool)
	connect                                func(string) (*pgx.Conn, error)
}

func verifyCombinedParentRecovery(t *testing.T, s combinedRecovery) {
	t.Helper()
	check := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatal(what)
		}
	}
	wait := func(what string, f func() bool) {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if f() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal(what)
	}
	wait("scoped parent did not expire", func() bool {
		_, err := s.vaultAdmin.Auth().Token().LookupAccessorWithContext(s.ctx, s.accessor)
		v, ok := err.(*vaultapi.ResponseError)
		return ok && v.StatusCode == http.StatusBadRequest
	})
	// This proof still resolves to a live, authorized caller. Only broker authority expired.
	identity, err := workloadidentity.New(s.identityConfig, s.store)
	check(err, "identity setup")
	if _, err := identity.ResolveForProxy(s.ctx, s.proof, ""); err != nil {
		t.Fatal("caller lost authorization before parent-expiry assertion")
	}
	s.request(s.proof, false)
	if conn, err := s.connect(s.proof); err == nil {
		_ = conn.Close(s.ctx)
		t.Fatal("expired parent admitted new PG session")
	}
	select {
	case err := <-s.queryDone:
		if err == nil {
			t.Fatal("active PG frontend query survived expiry")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active PG frontend query did not stop")
	}
	wait("expired parent left database role or session", func() bool {
		var count int
		return s.dbAdmin.QueryRow(s.ctx, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1)+(SELECT count(*) FROM pg_stat_activity WHERE usename=$1)", s.role).Scan(&count) == nil && count == 0
	})
	check(s.pg.Shutdown(s.ctx), "old PG shutdown")
	check(s.proxy.Shutdown(s.ctx), "old HTTP shutdown")
	// Expired cleanup authorization must preserve durable evidence for recovery.
	_ = s.minter.Close(s.ctx)
	pending, err := s.store.ListDatabaseCleanup(s.ctx)
	check(err, "read cleanup journal")
	if len(pending) != 1 || pending[0].LeaseID == "" {
		t.Fatal("known lease cleanup evidence was not retained")
	}
	check(s.store.Close(), "close persisted store")
	reopened, err := store.Open(s.storePath)
	check(err, "reopen persisted store")
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := reopened.ListDatabaseCleanup(s.ctx)
	check(err, "read reopened journal")
	if len(restored) != 1 || restored[0].LeaseID != pending[0].LeaseID {
		t.Fatal("cleanup evidence did not survive reopening")
	}
	parent, err := s.vaultAdmin.Auth().Token().CreateWithContext(s.ctx, &vaultapi.TokenCreateRequest{Policies: []string{s.policy, "agent-vault-database-parent", hashicorp.DatabaseCredentialPolicyName("database", "readonly")}, TTL: "2m"})
	check(err, "fresh parent login")
	t.Cleanup(func() {
		_ = s.vaultAdmin.Auth().Token().RevokeAccessorWithContext(context.Background(), parent.Auth.Accessor)
	})
	t.Setenv("VAULT_TOKEN", parent.Auth.ClientToken)
	hc, err := hashicorp.NewClient(s.ctx, slog.New(slog.DiscardHandler))
	check(err, "fresh Vault client")
	identity, err = workloadidentity.New(s.identityConfig, reopened)
	check(err, "reload caller bindings")
	provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{reopened}, make([]byte, 32))
	provider.RequestSecrets = hashicorp.RequestResolver{Store: reopened, Fetcher: hc}
	proxyURL, roots, proxy := setupProxy(t, identity, provider, func(o *Options) { o.StrictCredentialProxy = true; o.DurableAudit = requestlog.NewDurable(reopened) })
	destinationRoots := x509.NewCertPool()
	destinationRoots.AddCert(s.destination.Certificate())
	proxy.upstream.TLSClientConfig.RootCAs = destinationRoots
	outerHTTP := combinedTunnel(t, proxyURL.Host, s.destination.TLS.Certificates[0])
	roots.AddCert(s.destination.Certificate())
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "https", Host: outerHTTP}), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer " + s.proof}}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(s.ctx, http.MethodGet, s.destination.URL+"/approved", nil)
	check(err, "recovery HTTP request")
	request.Header.Set("Authorization", "Bearer __vault_API_KEY__")
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	check(err, "recovered HTTP admission")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("fresh parent denied admitted HTTP caller")
	}
	minter, err := pgproxy.NewDurableLeaseMinter(s.ctx, hc, reopened, pgproxy.DurableLeaseOptions{})
	check(err, "recovered durable minter")
	t.Cleanup(func() { _ = minter.Close(context.Background()) })
	wait("fresh parent did not reconcile retained journal", func() bool { rows, err := reopened.ListDatabaseCleanup(s.ctx); return err == nil && len(rows) == 0 })
	pg := pgproxy.New("127.0.0.1:0", pgproxy.Options{Auth: combinedAuth{identity}, Databases: combinedDatabase{pgproxy.DatabaseService{Name: "database", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: os.Getenv("AV_TEST_PG_DB"), Mount: "database", Role: "readonly", SSLMode: "disable"}}, Leases: minter, AuthorizationInterval: 25 * time.Millisecond})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	check(err, "recovery PG listener")
	go func() { _ = pg.Serve(ln) }()
	t.Cleanup(func() { _ = pg.Shutdown(context.Background()) })
	outerPG := combinedTunnel(t, ln.Addr().String(), s.destination.TLS.Certificates[0])
	cfg, err := pgx.ParseConfig("postgres://" + outerPG + "/database?sslmode=disable")
	check(err, "recovery PG config")
	cfg.User = "workload"
	cfg.Password = s.proof
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: &tls.Config{RootCAs: destinationRoots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}}).DialContext(ctx, "tcp", outerPG)
	}
	conn, err := pgx.ConnectConfig(s.ctx, cfg)
	check(err, "fresh parent denied admitted PG caller")
	var recoveredRole string
	check(conn.QueryRow(s.ctx, "SELECT current_user").Scan(&recoveredRole), "recovered PG query")
	_ = conn.Close(s.ctx)
	if recoveredRole == s.role || recoveredRole == "workload" {
		t.Fatal("recovery reused expired database identity")
	}
	wait("recovered session did not clean up", func() bool { rows, err := reopened.ListDatabaseCleanup(s.ctx); return err == nil && len(rows) == 0 })
	t.Log("real projected caller remained authorized; parent expiry denied HTTP and PG admission, terminated active proxied query, removed database role/session; persisted cleanup survived broker/store recreation and fresh login restored both protocols. Broker lifecycle recreation, not executable restart; local clients.")
}

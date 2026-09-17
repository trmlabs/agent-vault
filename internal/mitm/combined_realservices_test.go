//go:build realcombined

package mitm

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
)

type combinedAuth struct{ resolver *workloadidentity.Resolver }

func (a combinedAuth) Authenticate(ctx context.Context, token, vault string) (*pgproxy.AgentScope, error) {
	s, err := a.resolver.ResolveForProxy(ctx, token, vault)
	if err != nil {
		return nil, err
	}
	return &pgproxy.AgentScope{VaultID: s.VaultID, ActorID: s.AgentID, WorkloadID: s.WorkloadID}, nil
}

type combinedDatabase struct{ service pgproxy.DatabaseService }

func (r combinedDatabase) ResolveDatabase(_ context.Context, _ pgproxy.AgentScope, name string) (*pgproxy.DatabaseService, error) {
	if name != r.service.Name {
		return nil, errors.New("unknown fixture binding")
	}
	copy := r.service
	return &copy, nil
}

type combinedMinter struct {
	*pgproxy.DurableLeaseMinter
	mints atomic.Int64
}

func (m *combinedMinter) Mint(ctx context.Context, vault string, svc *pgproxy.DatabaseService) (*pgproxy.Lease, error) {
	m.mints.Add(1)
	return m.DurableLeaseMinter.Mint(ctx, vault, svc)
}

// The TLS tunnel is a disposable transport fixture, not deployment configuration.
// Pod mode exposes only the TLS listener; the broker target stays on loopback.
func combinedTunnel(t *testing.T, target string, cert tls.Certificate, publicPort ...string) string {
	t.Helper()
	address := "127.0.0.1:0"
	if os.Getenv("AV_COMBINED_POD_IP") != "" && len(publicPort) == 1 {
		address = "0.0.0.0:" + publicPort[0]
	}
	ln, err := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer func() { _ = conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func TestRealCombinedWorkloadProofVaultAndPostgres(t *testing.T) {
	runCombinedServices(t, false)
}

func runCombinedServices(t *testing.T, parentExpiry bool) {
	for _, name := range []string{"AV_TEST_WORKLOAD_CONFIG", "AV_TEST_WORKLOAD_PROOF", "AV_TEST_WORKLOAD_WRONG_PROOF", "VAULT_ADDR", "VAULT_TOKEN", "AV_TEST_PG_UPSTREAM", "AV_TEST_PG_ADMIN"} {
		if os.Getenv(name) == "" {
			t.Fatalf("combined fixture requires %s", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	readProof := func(name string) string {
		// Paths come from the disposable fixture runner, never an HTTP request.
		// #nosec G703
		data, err := os.ReadFile(os.Getenv(name))
		if err != nil {
			t.Fatal("cannot read projected fixture proof")
		}
		return strings.TrimSpace(string(data))
	}
	proof, wrongProof := readProof("AV_TEST_WORKLOAD_PROOF"), readProof("AV_TEST_WORKLOAD_WRONG_PROOF")
	storePath := filepath.Join(t.TempDir(), "combined.db")
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := st.CreateVault(ctx, "combined")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	agent, standing, err := st.CreateAgentWithGrantsAndToken(ctx, "combined", "fixture", "no-access", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "proxy"}}, &expires)
	if err != nil {
		t.Fatal(err)
	}
	identityConfig, err := workloadidentity.LoadConfig(os.Getenv("AV_TEST_WORKLOAD_CONFIG"))
	if err != nil || len(identityConfig.Bindings) != 1 {
		t.Fatal("invalid combined identity configuration")
	}
	identityConfig.Bindings[0].AgentID, identityConfig.Bindings[0].VaultID = agent.ID, v.ID
	identity, err := workloadidentity.New(identityConfig, st)
	if err != nil {
		t.Fatal(err)
	}
	if scope, err := identity.ResolveForProxy(ctx, proof, ""); err != nil || scope.WorkloadID == "" {
		t.Fatal("real projected proof did not authenticate")
	}
	admin, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	admin.SetToken(os.Getenv("VAULT_TOKEN"))
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	path := "combined-" + hex.EncodeToString(random[:])
	canary := hex.EncodeToString(random[:]) + "-first"
	var expected atomic.Value
	expected.Store(canary)
	writeKey := func(value string) {
		t.Helper()
		if _, err := admin.Logical().WriteWithContext(ctx, "secret/data/"+path, map[string]any{"data": map[string]any{"API_KEY": value}}); err != nil {
			t.Fatal("fixture Vault write failed")
		}
		expected.Store(value)
	}
	writeKey(canary)
	policy := "path \"secret/data/" + path + "\" { capabilities = [\"read\"] }"
	if err := admin.Sys().PutPolicyWithContext(ctx, path, policy); err != nil {
		t.Fatal("fixture policy creation failed")
	}
	parentTTL := "5m"
	if parentExpiry {
		parentTTL = "15s"
		role, err := admin.Logical().ReadWithContext(ctx, "database/roles/readonly")
		if err != nil || role == nil {
			t.Fatal("cannot read fixture database role")
		}
		extended := make(map[string]any, len(role.Data))
		for key, value := range role.Data {
			extended[key] = value
		}
		extended["default_ttl"] = "90s"
		if _, err := admin.Logical().WriteWithContext(ctx, "database/roles/readonly", extended); err != nil {
			t.Fatal("cannot extend fixture lease")
		}
		t.Cleanup(func() {
			_, _ = admin.Logical().WriteWithContext(context.Background(), "database/roles/readonly", role.Data)
		})
	}
	parent, err := admin.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{Policies: []string{path, "agent-vault-database-parent", hashicorp.DatabaseCredentialPolicyName("database", "readonly")}, TTL: parentTTL, ExplicitMaxTTL: parentTTL})
	if err != nil {
		t.Fatal("scoped fixture token creation failed")
	}
	t.Cleanup(func() { _ = admin.Auth().Token().RevokeAccessorWithContext(context.Background(), parent.Auth.Accessor) })
	t.Setenv("VAULT_TOKEN", parent.Auth.ClientToken)
	hc, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"` + path + `","kv_version":2}`, PollIntervalSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) || r.Header.Get("Proxy-Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "approved-output")
	}))
	t.Cleanup(destination.Close)
	u, _ := url.Parse(destination.URL)
	port, _ := strconv.Atoi(u.Port())
	services, _ := json.Marshal([]broker.Service{{Name: "read", Host: u.Hostname(), Port: &port, Path: "/approved", Auth: broker.Auth{Type: "passthrough"}, Substitutions: []broker.Substitution{{Key: "API_KEY", Placeholder: "__vault_API_KEY__", In: []string{"header"}}}}})
	if _, err := st.SetBrokerConfig(ctx, v.ID, string(services)); err != nil {
		t.Fatal(err)
	}
	provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, make([]byte, 32))
	provider.RequestSecrets = hashicorp.RequestResolver{Store: st, Fetcher: hc}
	proxyURL, roots, proxy := setupProxy(t, identity, provider, func(o *Options) { o.StrictCredentialProxy = true; o.DurableAudit = requestlog.NewDurable(st) })
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(destination.Certificate())
	proxy.upstream.TLSClientConfig.RootCAs = upstreamRoots
	cert := destination.TLS.Certificates[0]
	outerHTTP := combinedTunnel(t, proxyURL.Host, cert, "14443")
	roots.AddCert(destination.Certificate())
	denyUntrustedTransport := func(address string) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13})
		if err == nil {
			_ = conn.Close()
			t.Fatal("untrusted encrypted ingress certificate accepted")
		}
		plain, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = plain.Close() }()
		_ = plain.SetDeadline(time.Now().Add(time.Second))
		if _, err := plain.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, plain)
	}
	denyUntrustedTransport(outerHTTP)
	if calls.Load() != 0 {
		t.Fatal("invalid transport reached HTTP destination")
	}
	request := func(raw string, wantSuccess bool) {
		t.Helper()
		transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "https", Host: outerHTTP}), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer " + raw}}}
		defer transport.CloseIdleConnections()
		httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		r, _ := http.NewRequestWithContext(ctx, "GET", destination.URL+"/approved", nil)
		r.Header.Set("Authorization", "Bearer __vault_API_KEY__")
		before := calls.Load()
		resp, err := httpClient.Do(r)
		if err != nil {
			if wantSuccess {
				t.Fatal("encrypted HTTP request failed")
			}
		} else {
			data, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil || strings.Contains(string(data), expected.Load().(string)) {
				t.Fatal("invalid response or destination credential exposed")
			}
			if wantSuccess && (resp.StatusCode != 200 || string(data) != "approved-output") {
				t.Fatal("permitted HTTP request denied")
			}
			if !wantSuccess && resp.StatusCode < 400 {
				t.Fatal("forbidden HTTP request accepted")
			}
		}
		wantCalls := before
		if wantSuccess {
			wantCalls++
		}
		if calls.Load() != wantCalls {
			t.Fatal("unexpected destination request count")
		}
	}
	request(proof, true)
	writeKey(canary + "-rotated")
	request(proof, true)
	durable, err := pgproxy.NewDurableLeaseMinter(ctx, hc, st, pgproxy.DurableLeaseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close(context.Background()) })
	minter := &combinedMinter{DurableLeaseMinter: durable}
	pg := pgproxy.New("127.0.0.1:0", pgproxy.Options{Auth: combinedAuth{identity}, Databases: combinedDatabase{pgproxy.DatabaseService{Name: "database", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: os.Getenv("AV_TEST_PG_DB"), Mount: "database", Role: "readonly", SSLMode: "disable"}}, Leases: minter, AuthorizationInterval: 25 * time.Millisecond})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = pg.Serve(ln) }()
	t.Cleanup(func() { _ = pg.Shutdown(context.Background()) })
	outerPG := combinedTunnel(t, ln.Addr().String(), cert, "15443")
	denyUntrustedTransport(outerPG)
	plainConfig, err := pgx.ParseConfig("postgres://" + outerPG + "/database?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	plainConfig.User, plainConfig.Password = "workload", proof
	plainConfig.ConnectTimeout = time.Second
	if plain, err := pgx.ConnectConfig(ctx, plainConfig); err == nil {
		_ = plain.Close(ctx)
		t.Fatal("plaintext PostgreSQL startup accepted by encrypted ingress")
	}
	if minter.mints.Load() != 0 {
		t.Fatal("invalid transport minted database credentials")
	}
	if os.Getenv("AV_COMBINED_POD_IP") != "" {
		combinedInPodGate(t, ctx, destination.URL, proxy.RootPEM(), destination.Certificate().Raw)
	}
	connect := func(raw string) (*pgx.Conn, error) {
		cfg, err := pgx.ParseConfig("postgres://" + outerPG + "/database?sslmode=disable")
		if err != nil {
			return nil, err
		}
		cfg.User, cfg.Password = "workload", raw
		cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&tls.Dialer{Config: &tls.Config{RootCAs: upstreamRoots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}}).DialContext(ctx, "tcp", outerPG)
		}
		return pgx.ConnectConfig(ctx, cfg)
	}
	a, err := connect(proof)
	if err != nil {
		t.Fatal("real projected proof denied by encrypted PostgreSQL entry")
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	var role string
	if err := a.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role == "workload" {
		t.Fatal("database credential substitution failed")
	}
	for _, raw := range []string{standing.ID, wrongProof} {
		request(raw, false)
		before := minter.mints.Load()
		if denied, err := connect(raw); err == nil {
			_ = denied.Close(ctx)
			t.Fatal("forbidden PostgreSQL proof admitted")
		}
		if minter.mints.Load() != before {
			t.Fatal("denied proof minted credentials")
		}
	}
	dbAdmin, err := pgx.Connect(ctx, os.Getenv("AV_TEST_PG_ADMIN"))
	if err != nil {
		t.Fatal("database observation unavailable")
	}
	defer func() { _ = dbAdmin.Close(context.Background()) }()
	queryDone := make(chan error, 1)
	go func() { _, err := a.Exec(ctx, "SELECT pg_sleep(60)"); queryDone <- err }()
	startDeadline := time.Now().Add(3 * time.Second)
	for {
		var active bool
		if err := dbAdmin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND state='active' AND wait_event='PgSleep')", role).Scan(&active); err != nil {
			t.Fatal("running query observation failed")
		}
		if active {
			break
		}
		if time.Now().After(startDeadline) {
			t.Fatal("combined running query did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if parentExpiry {
		verifyCombinedParentRecovery(t, combinedRecovery{
			ctx: ctx, store: st, storePath: storePath, identityConfig: identityConfig, vaultAdmin: admin,
			accessor: parent.Auth.Accessor, policy: path, role: role, proof: proof,
			vaultID: v.ID, proxy: proxy, pg: pg, minter: durable, dbAdmin: dbAdmin,
			queryDone: queryDone, destination: destination, request: request, connect: connect,
		})
		return
	}
	// A real broker grant change must withdraw the same runtime proof on both paths.
	if err := st.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	request(proof, false)
	if denied, err := connect(proof); err == nil {
		_ = denied.Close(ctx)
		t.Fatal("revoked caller connected")
	}
	select {
	case err := <-queryDone:
		if err == nil {
			t.Fatal("revoked workload's running query completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked workload's running query did not stop")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var roles, sessions int
		if err := dbAdmin.QueryRow(ctx, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1), (SELECT count(*) FROM pg_stat_activity WHERE usename=$1)", role).Scan(&roles, &sessions); err != nil {
			t.Fatal("database cleanup observation failed")
		}
		if roles == 0 && sessions == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revocation incomplete: roles=%d sessions=%d", roles, sessions)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Log("actual Kubernetes projected proof + verified encrypted HTTP/PG ingress + live Vault + TLS HTTP destination + PostgreSQL passed; rotation immediate; wrong audience/standing token/revoked caller denied; database cleanup roles=0 sessions=0; local clients, no deployed bypass claim")
}

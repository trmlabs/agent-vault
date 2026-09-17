//go:build realvault

package pgproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
)

func realDurableInputs(t *testing.T) (*hashicorp.Client, *pgx.Conn, *DatabaseService) {
	t.Helper()
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("AV_TEST_PG_ADMIN") == "" || os.Getenv("AV_TEST_PG_UPSTREAM") == "" {
		t.Skip("requires disposable real Vault/PostgreSQL fixture")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, os.Getenv("AV_TEST_PG_ADMIN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })
	mount, role := os.Getenv("AV_TEST_VAULT_MOUNT"), os.Getenv("AV_TEST_VAULT_ROLE")
	if mount == "" {
		mount = "database"
	}
	if role == "" {
		role = "readonly"
	}
	api, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	api.SetToken(os.Getenv("VAULT_TOKEN"))
	parent, err := api.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{Policies: []string{"agent-vault-database-parent", hashicorp.DatabaseCredentialPolicyName(mount, role)}, TTL: "5m"})
	if err != nil {
		t.Fatal("create scoped fixture parent", err)
	}
	t.Cleanup(func() { _ = api.Auth().Token().RevokeAccessorWithContext(ctx, parent.Auth.Accessor) })
	t.Setenv("VAULT_TOKEN", parent.Auth.ClientToken)
	client, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	svc := &DatabaseService{Name: "durable", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: os.Getenv("AV_TEST_PG_DB"), Mount: mount, Role: role, SSLMode: "disable"}
	if svc.Database == "" {
		svc.Database = "appdb"
	}
	return client, admin, svc
}

func connectDurableLease(t *testing.T, svc *DatabaseService, lease *Lease) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig("postgres://" + svc.Addr + "/" + svc.Database + "?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = lease.Username, lease.Password
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("minted connection failed", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func assertDatabaseRemoved(t *testing.T, admin *pgx.Conn, username string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var roles, sessions int
		if err := admin.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1), (SELECT count(*) FROM pg_stat_activity WHERE usename=$1)`, username).Scan(&roles, &sessions); err != nil {
			t.Fatal(err)
		}
		if roles == 0 && sessions == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cleanup incomplete: roles=%d sessions=%d", roles, sessions)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestRealVault_DurableDatabaseCleanupFailure(t *testing.T) {
	client, admin, svc := realDurableInputs(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := newDurableForTest(t, client, st)
	ctx := context.Background()
	first, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	_ = connectDurableLease(t, svc, first)
	independent := connectDurableLease(t, svc, second)
	// A real database dependency prevents DROP ROLE. No forced revocation is used.
	schema := fmt.Sprintf("cleanup_fault_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()+" AUTHORIZATION "+pgx.Identifier{first.Username}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()) }()
	if err = m.Revoke(ctx, first.ID); err == nil {
		t.Fatal("database cleanup dependency failure accepted")
	}
	if _, err = m.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("unreconciled binding admitted")
	}
	var one int
	if err = independent.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatal("independent session interrupted", err)
	}
	if _, err = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	third, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal("restored cleanup did not recover", err)
	}
	assertDatabaseRemoved(t, admin, first.Username)
	if err = m.Revoke(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, second.Username)
	if err = m.Revoke(ctx, third.ID); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, third.Username)
	t.Logf("real database cleanup recovered in %s; residual roles=0 sessions=0; independent session remained usable", time.Since(started).Round(time.Millisecond))
}

func TestRealVault_DurableParentPolicyScope(t *testing.T) {
	client, _, svc := realDurableInputs(t)
	if _, err := client.NewDatabaseSession(context.Background(), svc.Mount, "readonly2", time.Minute); err == nil {
		t.Fatal("parent created token with an unattached role policy")
	}
	api, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	api.SetToken(os.Getenv("VAULT_TOKEN"))
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{"other credential role", func() error {
			_, err := api.Logical().ReadWithContext(context.Background(), "database/creds/readonly2")
			return err
		}},
		{"lease enumeration", func() error {
			_, err := api.Logical().ListWithContext(context.Background(), "sys/leases/lookup/database/creds/readonly")
			return err
		}},
		{"unrelated lease lookup", func() error {
			_, err := api.Logical().WriteWithContext(context.Background(), "sys/leases/lookup", map[string]any{"lease_id": "other/creds/admin/lease"})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var response *vaultapi.ResponseError
			err := test.run()
			if !errors.As(err, &response) || response.StatusCode != 403 {
				t.Fatalf("expected policy denial for %s", test.name)
			}
		})
	}
}

func TestRealVault_DurableInterruptedIssuance(t *testing.T) {
	_, admin, svc := realDurableInputs(t)
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	var failCleanup atomic.Bool
	failCleanup.Store(true)
	var interrupted atomic.Bool
	var orphanName atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-accessor" && failCleanup.Load() {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errors":["injected Vault outage"]}`))
			return
		}
		request := r.Clone(r.Context())
		request.RequestURI = ""
		request.URL.Scheme = upstream.Scheme
		request.URL.Host = upstream.Host
		response, err := http.DefaultTransport.RoundTrip(request)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			http.Error(w, "response unavailable", http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/v1/"+svc.Mount+"/creds/"+svc.Role && response.StatusCode == 200 && interrupted.CompareAndSwap(false, true) {
			var result struct {
				Data struct {
					Username string `json:"username"`
				} `json:"data"`
			}
			_ = json.Unmarshal(body, &result)
			orphanName.Store(result.Data.Username)
			_, _ = w.Write([]byte("lost issuance response"))
			return
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(body)
	}))
	defer proxy.Close()
	t.Setenv("VAULT_ADDR", proxy.URL)
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := newDurableForTest(t, client, st)
	ctx := context.Background()
	if _, err = m.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("lost issuance accepted")
	}
	if orphanName.Load() == nil || orphanName.Load().(string) == "" {
		t.Fatal("fixture did not observe actual issued role")
	}
	if err = m.Close(ctx); err == nil {
		t.Fatal("Vault cleanup outage accepted")
	}
	m2 := newDurableForTest(t, client, st)
	if _, err = m2.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("restart reopened unresolved binding")
	}
	failCleanup.Store(false)
	started := time.Now()
	if _, err = m2.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("unknown issuance automatically reopened")
	}
	assertDatabaseRemoved(t, admin, orphanName.Load().(string))
	records, err := st.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 1 {
		t.Fatal("missing quarantine", err)
	}
	if err = m2.ConfirmDatabaseCleanup(ctx, records[0].Accessor, "real fixture: matched issued username; observed zero roles and sessions after accessor revoke"); err != nil {
		t.Fatal(err)
	}
	lease, err := m2.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	if err = m2.Revoke(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, lease.Username)
	t.Logf("lost-response recovery completed in %s after explicit database reconciliation; residual roles=0 sessions=0; automatic reopening refused", time.Since(started).Round(time.Millisecond))
}

func TestRealVault_DurableCrashHelper(t *testing.T) {
	if os.Getenv("AV_DURABLE_CRASH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	ctx := context.Background()
	client, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(os.Getenv("AV_DURABLE_JOURNAL"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewDurableLeaseMinter(ctx, client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	svc := &DatabaseService{Name: "durable", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: os.Getenv("AV_TEST_PG_DB"), Mount: "database", Role: "readonly", SSLMode: "disable"}
	lease, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	conn := connectDurableLease(t, svc, lease)
	// The parent test supplies this path inside its private temporary directory.
	// #nosec G703
	if err = os.WriteFile(os.Getenv("AV_DURABLE_READY"), []byte(lease.Username), 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, "SELECT pg_sleep(60)")
	select {}
}

func TestRealVault_DurableProcessCrash(t *testing.T) {
	client, admin, svc := realDurableInputs(t)
	dir := t.TempDir()
	journal, ready := filepath.Join(dir, "cleanup.db"), filepath.Join(dir, "ready")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestRealVault_DurableCrashHelper$")
	child.Env = append(os.Environ(), "AV_DURABLE_CRASH_CHILD=1", "AV_DURABLE_JOURNAL="+journal, "AV_DURABLE_READY="+ready)
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	var username string
	observedActive := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(ready)
		if err == nil {
			username = string(data)
			var active int
			if err = admin.QueryRow(context.Background(), "SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND state='active'", username).Scan(&active); err != nil {
				t.Fatal(err)
			}
			if active == 1 {
				observedActive = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if username == "" || !observedActive {
		t.Fatal("crash helper did not start database work")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	st, err := store.Open(journal)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if early, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{}); err == nil {
		_ = early.Close(context.Background())
		t.Fatal("unexpired broker ownership stolen")
	}
	time.Sleep(3200 * time.Millisecond)
	started := time.Now()
	m := newDurableForTest(t, client, st)
	lease, err := m.Mint(context.Background(), "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, username)
	if err = m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, lease.Username)
	t.Logf("SIGKILL recovery completed in %s after owner expiry; residual roles=0 sessions=0", time.Since(started).Round(time.Millisecond))
}

func TestRealVault_DurableAuthorizationStopsOnlyAffectedQuery(t *testing.T) {
	for _, trigger := range []string{"actor-revocation", "binding-removal"} {
		t.Run(trigger, func(t *testing.T) {
			client, admin, svc := realDurableInputs(t)
			st, err := store.Open(filepath.Join(t.TempDir(), "cleanup.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			m := newDurableForTest(t, client, st)
			var removed atomic.Bool
			_, addr := startBroker(t, Options{Leases: m, AuthorizationInterval: 20 * time.Millisecond,
				Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
					if token != "actor-a" && token != "actor-b" {
						return nil, fmt.Errorf("unknown actor")
					}
					if trigger == "actor-revocation" && token == "actor-a" && removed.Load() {
						return nil, fmt.Errorf("revoked")
					}
					return &AgentScope{VaultID: "vault", ActorID: token, WorkloadID: token + "-pod"}, nil
				}),
				Databases: resolverFunc(func(_ context.Context, scope AgentScope, requested string) (*DatabaseService, error) {
					if requested != scope.ActorID {
						return nil, fmt.Errorf("wrong binding")
					}
					if trigger == "binding-removal" && requested == "actor-a" && removed.Load() {
						return nil, fmt.Errorf("binding removed")
					}
					copy := *svc
					copy.Name = requested
					return &copy, nil
				}),
			})
			connect := func(actor string) (*pgx.Conn, error) {
				cfg, err := pgx.ParseConfig("postgres://" + addr + "/" + actor + "?sslmode=disable")
				if err != nil {
					return nil, err
				}
				cfg.User, cfg.Password = "agent", actor
				return pgx.ConnectConfig(context.Background(), cfg)
			}
			a, err := connect("actor-a")
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close(context.Background())
			b, err := connect("actor-b")
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(context.Background())
			var username string
			if err = a.QueryRow(context.Background(), "SELECT current_user").Scan(&username); err != nil {
				t.Fatal(err)
			}
			aDone, bDone := make(chan error, 1), make(chan error, 1)
			go func() { _, err := a.Exec(context.Background(), "SELECT pg_sleep(20)"); aDone <- err }()
			go func() { _, err := b.Exec(context.Background(), "SELECT pg_sleep(1)"); bDone <- err }()
			waitFor(t, time.Second, func() bool {
				var active int
				err := admin.QueryRow(context.Background(), "SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND state='active'", username).Scan(&active)
				return err == nil && active == 1
			}, "affected query never started")
			removed.Store(true)
			select {
			case err := <-aDone:
				if err == nil {
					t.Fatal("affected query completed")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("affected query kept running")
			}
			assertDatabaseRemoved(t, admin, username)
			select {
			case err := <-bDone:
				if err != nil {
					t.Fatal("independent query failed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("independent query did not finish")
			}
			if denied, err := connect("actor-a"); err == nil {
				_ = denied.Close(context.Background())
				t.Fatal("new work accepted after removal")
			}
			t.Log("real Vault/PostgreSQL session terminated; second caller's running query completed; new affected work denied; identity callback synthetic")
		})
	}
}

func TestRealVault_DurableChildExpiryStopsRunningQuery(t *testing.T) {
	client, admin, svc := realDurableInputs(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{TokenTTL: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	_, addr := startBroker(t, Options{Leases: m, Auth: &fakeAuth{scope: &AgentScope{VaultID: "vault", ActorID: "actor"}}, Databases: &fakeResolver{svc: svc}})
	cfg, err := pgx.ParseConfig("postgres://" + addr + "/durable?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = "agent", "synthetic-identity"
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var username string
	if err = conn.QueryRow(context.Background(), "SELECT current_user").Scan(&username); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	done := make(chan error, 1)
	go func() { _, err := conn.Exec(context.Background(), "SELECT pg_sleep(20)"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("query survived child-token expiry")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expired query kept running")
	}
	assertDatabaseRemoved(t, admin, username)
	fresh, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("fresh permitted session failed", err)
	}
	_ = fresh.Close(context.Background())
	t.Logf("child-token expiry terminated active query in %s; residual roles=0 sessions=0; fresh authorized connection succeeded", time.Since(started).Round(time.Millisecond))
}

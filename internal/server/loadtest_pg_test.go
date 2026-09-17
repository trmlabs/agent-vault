//go:build loadpg

// Scale / stress harness for the PostgreSQL broker, guarded by the `loadpg`
// build tag and skipped unless pointed at a running Vault (database engine
// configured) + PostgreSQL. It models a CRM deploying many agents that open DB
// connections through the broker, and asserts the three scaling invariants:
// no dangling connections/roles under churn, a bounded connection count (the DB
// is never saturated beyond the cap), and long-lived sessions surviving churn.
//
//	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
//	AV_TEST_VAULT_MOUNT=database AV_TEST_VAULT_ROLE=readonly \
//	AV_TEST_PG_UPSTREAM=127.0.0.1:5433 AV_TEST_PG_DB=appdb \
//	AV_TEST_PG_ADMIN='postgres://vault_admin:vault-bootstrap-pw@127.0.0.1:5433/appdb?sslmode=disable' \
//	go test -tags loadpg ./internal/server/ -run LoadPG -v -timeout 15m
package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/jackc/pgx/v5"
)

// loadAuth maps each token to its own actor id, modeling distinct agents (so
// the per-actor lease cap does not conflate independent agents).
type loadAuth struct{}

func (loadAuth) Authenticate(_ context.Context, token, _ string) (*pgproxy.AgentScope, error) {
	return &pgproxy.AgentScope{VaultID: "vault-load", VaultName: "load", ActorID: token}, nil
}

type loadEnv struct {
	mount, role, upstream, database, adminDSN string
}

func loadEnvOrSkip(t *testing.T) loadEnv {
	t.Helper()
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("AV_TEST_PG_UPSTREAM") == "" || os.Getenv("AV_TEST_PG_ADMIN") == "" {
		t.Skip("set VAULT_ADDR (+token), AV_TEST_PG_UPSTREAM, AV_TEST_PG_DB, AV_TEST_PG_ADMIN to run the load test")
	}
	return loadEnv{
		mount:    getenvDefault("AV_TEST_VAULT_MOUNT", "database"),
		role:     getenvDefault("AV_TEST_VAULT_ROLE", "readonly"),
		upstream: os.Getenv("AV_TEST_PG_UPSTREAM"),
		database: getenvDefault("AV_TEST_PG_DB", "appdb"),
		adminDSN: os.Getenv("AV_TEST_PG_ADMIN"),
	}
}

func getenvDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func buildLoadBroker(t *testing.T, env loadEnv, maxConns int) (*pgproxy.Broker, string) {
	t.Helper()
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	svc := pgproxy.DatabaseService{Name: "load", Addr: env.upstream, Database: env.database, Mount: env.mount, Role: env.role, SSLMode: "disable"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	broker := pgproxy.New(ln.Addr().String(), pgproxy.Options{
		Auth:      loadAuth{},
		Databases: NewStaticDatabaseResolver(map[string][]pgproxy.DatabaseService{"load": {svc}}),
		Leases:    NewVaultLeaseMinter(client),
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxConns:  maxConns,
	})
	go func() { _ = broker.Serve(ln) }()
	t.Cleanup(func() { _ = broker.Shutdown(context.Background()) })
	return broker, ln.Addr().String()
}

// countMinted returns the number of live upstream connections and the number of
// dangling roles whose names Vault generated (prefix "v-").
func countMinted(t *testing.T, admin *pgx.Conn) (conns, roles int) {
	t.Helper()
	ctx := context.Background()
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename LIKE 'v-%'").Scan(&conns); err != nil {
		t.Fatalf("count conns: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-%'").Scan(&roles); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	return conns, roles
}

func connectAgent(ctx context.Context, addr, token, database string) (*pgx.Conn, error) {
	return pgx.Connect(ctx, fmt.Sprintf("postgres://agent:%s@%s/%s?sslmode=prefer", token, addr, database))
}

// TestLoadPG_ChurnNoDangling drives many short-lived connect->query->disconnect
// cycles from distinct agents and asserts that upstream connections, dangling
// roles, and goroutines all return to baseline.
func TestLoadPG_ChurnNoDangling(t *testing.T) {
	env := loadEnvOrSkip(t)
	total := intEnv("AV_LOAD_TOTAL", 200)
	concurrency := intEnv("AV_LOAD_CONCURRENCY", 40)

	admin, err := pgx.Connect(context.Background(), env.adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	_, addr := buildLoadBroker(t, env, 128)

	baseConns, baseRoles := countMinted(t, admin)
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	var peak int64
	stopSampler := make(chan struct{})
	var samplerDone sync.WaitGroup
	samplerDone.Add(1)
	go func() {
		defer samplerDone.Done()
		for {
			select {
			case <-stopSampler:
				return
			case <-time.After(40 * time.Millisecond):
				c, _ := countMinted(t, admin)
				for {
					p := atomic.LoadInt64(&peak)
					if int64(c) <= p || atomic.CompareAndSwapInt64(&peak, p, int64(c)) {
						break
					}
				}
			}
		}
	}()

	latencies := make(chan time.Duration, total)
	var okCount, errCount int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i := 0; i < total; i++ {
		wg.Add(1)
		token := fmt.Sprintf("agent-%d", i)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			started := time.Now()
			conn, err := connectAgent(ctx, addr, token, env.database)
			latencies <- time.Since(started)
			if err != nil {
				atomic.AddInt64(&errCount, 1)
				return
			}
			var n int
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM customers").Scan(&n); err != nil {
				atomic.AddInt64(&errCount, 1)
			} else {
				atomic.AddInt64(&okCount, 1)
			}
			_ = conn.Close(ctx)
		}()
	}
	wg.Wait()
	close(stopSampler)
	samplerDone.Wait()

	t.Logf("churn: total=%d concurrency=%d ok=%d err=%d peak_upstream_conns=%d",
		total, concurrency, okCount, errCount, atomic.LoadInt64(&peak))

	close(latencies)
	samples := make([]time.Duration, 0, total)
	for latency := range latencies {
		samples = append(samples, latency)
	}
	slices.Sort(samples)
	if len(samples) > 0 {
		t.Logf("connect latency (including failed attempts): p50=%s p95=%s p99=%s", samples[(len(samples)-1)*50/100], samples[(len(samples)-1)*95/100], samples[(len(samples)-1)*99/100])
	}

	// Settle: upstream connections and roles must drain back to baseline.
	waitForDrain(t, admin, baseConns, baseRoles, 30*time.Second)

	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	if delta := endGoroutines - baseGoroutines; delta > total/10+20 {
		t.Errorf("goroutine leak: baseline=%d end=%d delta=%d", baseGoroutines, endGoroutines, delta)
	}
	if errCount != 0 {
		t.Errorf("too many errors under churn: %d/%d", errCount, total)
	}
}

// TestLoadPG_SaturationCap offers far more concurrent connections than the
// broker's MaxConns and asserts the upstream DB connection count never exceeds
// the cap (the database is never saturated), while nothing dangles afterward.
func TestLoadPG_SaturationCap(t *testing.T) {
	env := loadEnvOrSkip(t)
	const maxConns = 15
	offered := intEnv("AV_LOAD_OFFERED", 80)

	admin, err := pgx.Connect(context.Background(), env.adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	_, addr := buildLoadBroker(t, env, maxConns)
	baseConns, baseRoles := countMinted(t, admin)

	// Hold connections open so the cap is under sustained pressure.
	release := make(chan struct{})
	var wg sync.WaitGroup
	var held int64
	for i := 0; i < offered; i++ {
		wg.Add(1)
		token := fmt.Sprintf("burst-%d", i)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := connectAgent(ctx, addr, token, env.database)
			if err != nil {
				return
			}
			atomic.AddInt64(&held, 1)
			<-release
			_ = conn.Close(context.Background())
		}()
	}

	// Sample the upstream connection count while the burst is held.
	var peak int
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		c, _ := countMinted(t, admin)
		if c > peak {
			peak = c
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("saturation: offered=%d max_conns=%d peak_upstream_conns=%d held=%d", offered, maxConns, peak, atomic.LoadInt64(&held))
	if peak > maxConns {
		t.Errorf("DB saturation: peak upstream connections %d exceeded MaxConns %d", peak, maxConns)
	}
	close(release)
	wg.Wait()
	waitForDrain(t, admin, baseConns, baseRoles, 30*time.Second)
}

// TestLoadPG_LongLivedUnderChurn holds a cohort of long-lived sessions open and
// keeps them usable while short-lived churn runs around them.
func TestLoadPG_LongLivedUnderChurn(t *testing.T) {
	env := loadEnvOrSkip(t)
	admin, err := pgx.Connect(context.Background(), env.adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	_, addr := buildLoadBroker(t, env, 128)
	baseConns, baseRoles := countMinted(t, admin)

	const longLived = 10
	longConns := make([]*pgx.Conn, 0, longLived)
	for i := 0; i < longLived; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := connectAgent(ctx, addr, fmt.Sprintf("long-%d", i), env.database)
		cancel()
		if err != nil {
			t.Fatalf("open long-lived session %d: %v", i, err)
		}
		longConns = append(longConns, conn)
	}

	// Churn short-lived connections concurrently.
	stop := make(chan struct{})
	var churnWG sync.WaitGroup
	for w := 0; w < 20; w++ {
		churnWG.Add(1)
		go func(w int) {
			defer churnWG.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if conn, err := connectAgent(ctx, addr, fmt.Sprintf("churn-%d-%d", w, i), env.database); err == nil {
					_, _ = conn.Exec(ctx, "SELECT 1")
					_ = conn.Close(ctx)
				}
				cancel()
			}
		}(w)
	}

	// Repeatedly exercise the long-lived sessions during the churn window.
	for round := 0; round < 5; round++ {
		time.Sleep(600 * time.Millisecond)
		for i, conn := range longConns {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var one int
			if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
				cancel()
				t.Fatalf("long-lived session %d broke during churn (round %d): %v", i, round, err)
			}
			cancel()
		}
	}
	close(stop)
	churnWG.Wait()

	for _, conn := range longConns {
		_ = conn.Close(context.Background())
	}
	waitForDrain(t, admin, baseConns, baseRoles, 30*time.Second)
}

// TestLoadPG_RenewalRealVault holds a session open across several role TTLs and
// asserts it stays usable — exercising real Vault lease renewal end to end.
// Requires the Vault role's default_ttl to be short (e.g. 8s) and max_ttl
// comfortably larger than the hold window.
func TestLoadPG_RenewalRealVault(t *testing.T) {
	env := loadEnvOrSkip(t)
	hold := time.Duration(intEnv("AV_LOAD_RENEW_HOLD_SEC", 22)) * time.Second

	admin, err := pgx.Connect(context.Background(), env.adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	_, addr := buildLoadBroker(t, env, 128)
	baseConns, baseRoles := countMinted(t, admin)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, err := connectAgent(ctx, addr, "renew-agent", env.database)
	cancel()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	deadline := time.Now().Add(hold)
	queries := 0
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		qctx, qcancel := context.WithTimeout(context.Background(), 5*time.Second)
		var one int
		err := conn.QueryRow(qctx, "SELECT 1").Scan(&one)
		qcancel()
		if err != nil {
			_ = conn.Close(context.Background())
			t.Fatalf("session broke after %d successful queries (~%s in) — real Vault renewal failed: %v", queries, time.Until(deadline.Add(-hold)).Abs(), err)
		}
		queries++
	}
	t.Logf("session survived %s (%d queries) across real Vault renewals", hold, queries)
	_ = conn.Close(context.Background())
	waitForDrain(t, admin, baseConns, baseRoles, 30*time.Second)
}

// TestLoadPG_AbruptTermination hard-closes the TCP socket mid-session (RST)
// across many iterations and asserts nothing dangles — the teardown path must
// fire on abnormal termination, not just clean disconnects.
func TestLoadPG_AbruptTermination(t *testing.T) {
	env := loadEnvOrSkip(t)
	iterations := intEnv("AV_LOAD_ABRUPT", 120)

	admin, err := pgx.Connect(context.Background(), env.adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	_, addr := buildLoadBroker(t, env, 64)
	baseConns, baseRoles := countMinted(t, admin)
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	sem := make(chan struct{}, 30)
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		token := fmt.Sprintf("abrupt-%d", i)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://agent:%s@%s/%s?sslmode=prefer", token, addr, env.database))
			if err != nil {
				return
			}
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				return
			}
			// Establish the session, then hard-close the underlying socket
			// (RST-like) without a clean Terminate.
			var n int
			_ = conn.QueryRow(ctx, "SELECT count(*) FROM customers").Scan(&n)
			if raw := conn.PgConn().Conn(); raw != nil {
				if tcp, ok := raw.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0) // force RST on close
				}
				_ = raw.Close()
			}
		}()
	}
	wg.Wait()

	waitForDrain(t, admin, baseConns, baseRoles, 30*time.Second)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	if delta := runtime.NumGoroutine() - baseGoroutines; delta > iterations/10+20 {
		t.Errorf("goroutine leak after abrupt termination: baseline=%d end=%d delta=%d", baseGoroutines, runtime.NumGoroutine(), delta)
	}
}

// waitForDrain polls until upstream connections and roles return to baseline,
// failing with the observed counts if they do not (a dangling leak).
func waitForDrain(t *testing.T, admin *pgx.Conn, baseConns, baseRoles int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		conns, roles := countMinted(t, admin)
		if conns <= baseConns && roles <= baseRoles {
			t.Logf("drained cleanly: upstream_conns=%d roles=%d (baseline %d/%d)", conns, roles, baseConns, baseRoles)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DANGLING after %s: upstream_conns=%d (base %d), dangling roles=%d (base %d)", timeout, conns, baseConns, roles, baseRoles)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Two Vault roles and two databases share one broker; saturating their shared
// endpoint must not misroute a session or leave generated roles behind.
func TestLoadPG_MultipleDatabases(t *testing.T) {
	env := loadEnvOrSkip(t)
	secondDB, secondRole := os.Getenv("AV_TEST_PG_SECOND_DB"), os.Getenv("AV_TEST_VAULT_SECOND_ROLE")
	if secondDB == "" || secondRole == "" {
		t.Skip("requires second database/role fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := hashicorp.NewClient(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, env.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	initialConns, initialRoles := countMinted(t, admin)
	services := []pgproxy.DatabaseService{
		{Name: "first", Addr: env.upstream, Database: env.database, Mount: env.mount, Role: env.role, SSLMode: "disable", MaxConns: 8},
		{Name: "second", Addr: env.upstream, Database: secondDB, Mount: env.mount, Role: secondRole, SSLMode: "disable", MaxConns: 8},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	broker := pgproxy.New(ln.Addr().String(), pgproxy.Options{Auth: loadAuth{}, Databases: NewStaticDatabaseResolver(map[string][]pgproxy.DatabaseService{"load": services}), Leases: NewVaultLeaseMinter(client), MaxConns: 12})
	go func() { _ = broker.Serve(ln) }()
	defer broker.Shutdown(context.Background())
	type result struct {
		conn *pgx.Conn
		err  error
	}
	results := make(chan result, 8)
	for i := range 8 {
		go func() {
			svc := services[i%2]
			conn, err := connectAgent(ctx, ln.Addr().String(), fmt.Sprintf("actor-%d", i), svc.Name)
			if err == nil {
				var db string
				err = conn.QueryRow(ctx, "SELECT current_database()").Scan(&db)
				if err == nil && db != svc.Database {
					err = fmt.Errorf("misrouted %s to %s", svc.Name, db)
				}
			}
			results <- result{conn, err}
		}()
	}
	conns := make([]*pgx.Conn, 0, 8)
	for range 8 {
		r := <-results
		if r.conn != nil {
			conns = append(conns, r.conn)
		}
		if r.err != nil {
			t.Error(r.err)
		}
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close(context.Background())
		}
	}()
	if t.Failed() {
		return
	}
	excess, err := connectAgent(ctx, ln.Addr().String(), "excess", "second")
	if err == nil {
		_ = excess.Close(ctx)
		t.Fatal("shared endpoint budget exceeded across databases")
	}
	for _, conn := range conns {
		_ = conn.Close(ctx)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		nc, nr := countMinted(t, admin)
		if nc == initialConns && nr == initialRoles {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("multi-database sessions did not drain their roles and connections")
}

func TestLoadPG_DisconnectStopsActiveQuery(t *testing.T) {
	env := loadEnvOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, env.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	nc, nr := countMinted(t, admin)
	_, addr := buildLoadBroker(t, env, 4)
	agent, err := connectAgent(ctx, addr, "disconnect-active", "load")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close(context.Background())
	var role string
	if err := agent.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := agent.Exec(ctx, "SELECT pg_sleep(60)"); done <- err }()
	running := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND query='SELECT pg_sleep(60)' AND state='active')", role).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !running {
		t.Fatal("query did not start")
	}
	// Simulate a crashed client without sending a protocol Terminate or Cancel.
	_ = agent.PgConn().Conn().Close()
	<-done
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		nowC, nowR := countMinted(t, admin)
		if nowC == nc && nowR == nr {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("client disconnect left an active query or role; verify revocation terminates the minted user's backends")
}

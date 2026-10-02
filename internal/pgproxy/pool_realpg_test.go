//go:build realpg

package pgproxy

// Transaction-mode multiplexing against a real PostgreSQL. Requires
// AV_TEST_PG_POOL_ADMIN, an admin DSN for a disposable server, for example
// postgres://postgres:<password>@127.0.0.1:55434/postgres?sslmode=disable.
// The tests create their own roles and database objects with synthetic
// passwords and drop them afterwards.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

type poolEnv struct {
	t      *testing.T
	admin  *pgx.Conn
	db     string
	roles  []string // alternate per mint, so a rotation is visible
	pw     string
	upAddr string
}

func newPoolEnv(t *testing.T) *poolEnv {
	t.Helper()
	dsn := os.Getenv("AV_TEST_PG_POOL_ADMIN")
	if dsn == "" {
		t.Skip("set AV_TEST_PG_POOL_ADMIN")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })
	u, _ := url.Parse(dsn)
	suffix := randomHex(4)
	e := &poolEnv{t: t, admin: admin, db: u.Path[1:], pw: randomHex(16), upAddr: u.Host,
		roles: []string{"pool_a_" + suffix, "pool_b_" + suffix}}
	for _, role := range e.roles {
		e.exec(fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, e.pw))
		e.exec(fmt.Sprintf("GRANT ALL ON SCHEMA public TO %s", role))
		e.exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS other_%s", suffix))
		e.exec(fmt.Sprintf("GRANT ALL ON SCHEMA other_%s TO %s", suffix, role))
	}
	e.exec(fmt.Sprintf("CREATE TABLE pool_items_%s (id serial primary key, worker int, n int)", suffix))
	for _, role := range e.roles {
		e.exec(fmt.Sprintf("GRANT ALL ON pool_items_%s, pool_items_%s_id_seq TO %s", suffix, suffix, role))
	}
	t.Cleanup(func() {
		e.exec(fmt.Sprintf("DROP TABLE IF EXISTS pool_items_%s", suffix))
		for _, role := range e.roles {
			e.exec(fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s'", role))
			e.exec(fmt.Sprintf("REVOKE ALL ON SCHEMA public FROM %s", role))
			e.exec(fmt.Sprintf("DROP SCHEMA IF EXISTS other_%s CASCADE", suffix))
			e.exec(fmt.Sprintf("DROP ROLE IF EXISTS %s", role))
		}
	})
	return e
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *poolEnv) exec(sql string) {
	e.t.Helper()
	if _, err := e.admin.Exec(context.Background(), sql); err != nil {
		e.t.Fatalf("%s: %v", strings.SplitN(sql, " ", 3)[:2], err)
	}
}

func (e *poolEnv) table() string { return "pool_items_" + strings.TrimPrefix(e.roles[0], "pool_a_") }

// serverConns counts the broker's server connections per role.
func (e *poolEnv) serverConns() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	rows, err := e.admin.Query(context.Background(), "SELECT usename, count(*) FROM pg_stat_activity WHERE usename = ANY($1) GROUP BY usename", e.roles)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int
		_ = rows.Scan(&name, &n)
		out[name] = n
	}
	return out
}

// rotatingMinter hands out the test roles alternately, with a fixed lifetime.
type rotatingMinter struct {
	env     *poolEnv
	life    time.Duration
	mu      sync.Mutex
	mints   int
	revoked []string
}

func (m *rotatingMinter) Mint(_ context.Context, _ string, _ *DatabaseService) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	role := m.env.roles[m.mints%len(m.env.roles)]
	m.mints++
	return &Lease{ID: fmt.Sprintf("lease-%d-%s", m.mints, role), Username: role, Password: m.env.pw, ExpiresAt: time.Now().Add(m.life)}, nil
}
func (m *rotatingMinter) Renew(context.Context, string, time.Duration) (time.Time, error) {
	return time.Time{}, errors.New("pooled credentials rotate instead")
}
func (m *rotatingMinter) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	m.revoked = append(m.revoked, id)
	m.mu.Unlock()
	return nil
}
func (m *rotatingMinter) counts() (int, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mints, append([]string(nil), m.revoked...)
}

type poolFixture struct {
	env    *poolEnv
	broker *Broker
	addr   string
	minter *rotatingMinter
	audit  *recordingAudit
}

func newPoolFixture(t *testing.T, budget int, life time.Duration, opts PoolOptions) *poolFixture {
	t.Helper()
	env := newPoolEnv(t)
	f := &poolFixture{env: env, minter: &rotatingMinter{env: env, life: life}, audit: &recordingAudit{}}
	f.broker, f.addr = startBroker(t, Options{
		Auth:              &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-uid-1", Pool: "cursor"}},
		Databases:         &fakeResolver{svc: &DatabaseService{Name: "core", Addr: env.upAddr, Database: env.db, Mount: "database", Role: "r", SSLMode: "disable", MaxConns: budget}},
		Leases:            f.minter,
		MaxConns:          500,
		MaxLeasesPerActor: 500,
		AdmissionTimeout:  5 * time.Second,
		Pool:              &opts,
		Audit:             f.audit,
	})
	return f
}

func (f *poolFixture) connect(t *testing.T, params map[string]string) *pgx.Conn {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	config, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%s user=workload password=agent-token dbname=core sslmode=disable", host, port))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range params {
		config.RuntimeParams[k] = v
	}
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func TestRealPostgres_PoolMultiplexesManyClients(t *testing.T) {
	f := newPoolFixture(t, 3, time.Hour, PoolOptions{QueueFactor: 10})
	ctx := context.Background()
	table := f.env.table()
	var peak atomic.Int32
	stop, monitored := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(monitored)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			total := 0
			for _, n := range f.env.serverConns() {
				total += n
			}
			if int32(total) > peak.Load() {
				peak.Store(int32(total))
			}
		}
	}()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for worker := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := f.connect(t, nil)
			for i := range 10 {
				tx, err := conn.Begin(ctx)
				if err != nil {
					errs <- err
					return
				}
				if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (worker, n) VALUES ($1, $2)", worker, i); err != nil {
					errs <- err
					return
				}
				var mine int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE worker = $1", worker).Scan(&mine); err != nil || mine != i+1 {
					errs <- fmt.Errorf("worker %d saw %d rows in its transaction: %v", worker, mine, err)
					return
				}
				if err := tx.Commit(ctx); err != nil {
					errs <- err
					return
				}
				var sum int
				if err := conn.QueryRow(ctx, "SELECT $1::int + $2::int", i, worker).Scan(&sum); err != nil || sum != i+worker {
					errs <- fmt.Errorf("prepared arithmetic: %d %v", sum, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-monitored
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var rows int
	if err := f.env.admin.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&rows); err != nil || rows != 200 {
		t.Fatalf("committed rows = %d %v", rows, err)
	}
	if p := peak.Load(); p > 3 || p == 0 {
		t.Fatalf("20 clients used %d server connections, budget 3", p)
	}
	if mints, _ := f.minter.counts(); mints != 1 {
		t.Fatalf("minted %d credentials, want 1 shared credential", mints)
	}
	transactions := 0
	for _, e := range f.audit.recorded() {
		if e.Event == auditchain.EventTransaction && e.Outcome == "completed" && e.Pool == "cursor" {
			transactions++
		}
	}
	if transactions < 400 {
		t.Fatalf("audited %d transactions, want at least 400", transactions)
	}
}

// Clients that reuse a statement name for different queries never see each
// other's statement, even on one shared server connection.
func TestRealPostgres_PoolPreparedStatementsAreIsolated(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	ctx := context.Background()
	a, b := f.connect(t, nil).PgConn(), f.connect(t, nil).PgConn()
	if _, err := a.Prepare(ctx, "s1", "SELECT 'from-a'::text", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prepare(ctx, "s1", "SELECT 'from-b'::text", nil); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		for conn, want := range map[*pgconn.PgConn]string{a: "from-a", b: "from-b"} {
			result := conn.ExecPrepared(ctx, "s1", nil, nil, nil).Read()
			if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][0]) != want {
				t.Fatalf("statement s1 returned %q, want %q: %v", result.Rows, want, result.Err)
			}
		}
	}
	if err := a.Deallocate(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if result := b.ExecPrepared(ctx, "s1", nil, nil, nil).Read(); result.Err != nil {
		t.Fatalf("closing a's statement broke b's: %v", result.Err)
	}
}

// Session state pins the connection to its client, and is wiped before the
// connection serves anyone else.
func TestRealPostgres_PoolSessionStateNeverLeaks(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{SessionShare: 1})
	ctx := context.Background()
	schema := "other_" + strings.TrimPrefix(f.env.roles[0], "pool_a_")
	a := f.connect(t, nil)
	if _, err := a.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exec(ctx, "CREATE TEMP TABLE scratch (id int)"); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := a.QueryRow(ctx, "SHOW search_path").Scan(&path); err != nil || path != schema {
		t.Fatalf("pinned session lost its search_path: %q %v", path, err)
	}
	_ = a.Close(ctx)
	b := f.connect(t, nil)
	if err := b.QueryRow(ctx, "SHOW search_path").Scan(&path); err != nil || strings.Contains(path, schema) {
		t.Fatalf("search_path leaked to the next client: %q %v", path, err)
	}
	if _, err := b.Exec(ctx, "SELECT * FROM scratch"); err == nil {
		t.Fatal("temp table leaked to the next client")
	}
}

func TestRealPostgres_PoolStartupParametersFollowTheClient(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	ctx := context.Background()
	tokyo := f.connect(t, map[string]string{"TimeZone": "Asia/Tokyo"})
	plain := f.connect(t, nil)
	for range 3 {
		var tz string
		if err := tokyo.QueryRow(ctx, "SHOW TimeZone").Scan(&tz); err != nil || tz != "Asia/Tokyo" {
			t.Fatalf("client parameter not applied: %q %v", tz, err)
		}
		if err := plain.QueryRow(ctx, "SHOW TimeZone").Scan(&tz); err != nil || tz == "Asia/Tokyo" {
			t.Fatalf("another client's parameter leaked: %q %v", tz, err)
		}
	}
}

func TestRealPostgres_PoolRefusesBeyondBudgetAndSessionShare(t *testing.T) {
	f := newPoolFixture(t, 2, time.Hour, PoolOptions{QueueWait: 300 * time.Millisecond, SessionShare: 0.1})
	ctx := context.Background()
	pinned := f.connect(t, nil)
	if _, err := pinned.Exec(ctx, "SET statement_timeout = 60000"); err != nil {
		t.Fatal(err)
	}
	second := f.connect(t, nil)
	var pgErr *pgconn.PgError
	if _, err := second.Exec(ctx, "SET statement_timeout = 1000"); !errors.As(err, &pgErr) || pgErr.Code != "53300" {
		t.Fatalf("second pin beyond the share: %v", err)
	}
	if _, err := second.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("a refused pin broke the session: %v", err)
	}
	tx, err := second.Begin(ctx) // holds the last connection
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	third := f.connect(t, nil)
	started := time.Now()
	if _, err := third.Exec(ctx, "SELECT 1"); !errors.As(err, &pgErr) || pgErr.Code != "53300" {
		t.Fatalf("checkout beyond the budget: %v", err)
	}
	if waited := time.Since(started); waited < 250*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("queue wait %v, want about 300ms", waited)
	}
}

// A client that disconnects inside a transaction never hands its open
// transaction to the next client.
func TestRealPostgres_PoolDiscardsConnectionsLeftInATransaction(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	ctx := context.Background()
	table := f.env.table()
	a := f.connect(t, nil)
	tx, err := a.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (worker, n) VALUES (99, 1)"); err != nil {
		t.Fatal(err)
	}
	_ = a.PgConn().Conn().Close() // vanish mid-transaction
	b := f.connect(t, nil)
	var n int
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := b.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE worker = 99").Scan(&n)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("next client never got a connection: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 0 {
		t.Fatal("an abandoned transaction's write became visible")
	}
}

// Rotation mints the next credential at half life; new connections use it,
// a transaction on the old one finishes, and the old one is revoked only after.
func TestRealPostgres_PoolRotatesWithoutCuttingTransactions(t *testing.T) {
	f := newPoolFixture(t, 4, 14*time.Second, PoolOptions{})
	ctx := context.Background()
	long := f.connect(t, nil)
	tx, err := long.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second) // past the rotation point
	if mints, revoked := f.minter.counts(); mints != 2 || len(revoked) != 0 {
		t.Fatalf("after rotation: mints=%d revoked=%v; the busy old credential must stay", mints, revoked)
	}
	other := f.connect(t, nil)
	var user string
	if err := other.QueryRow(ctx, "SELECT current_user").Scan(&user); err != nil || user != f.env.roles[1] {
		t.Fatalf("new connection used %q, want the rotated role %q: %v", user, f.env.roles[1], err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("rotation cut the open transaction: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, revoked := f.minter.counts(); len(revoked) == 1 && strings.HasSuffix(revoked[0], f.env.roles[0]) {
			break
		}
		if time.Now().After(deadline) {
			_, revoked := f.minter.counts()
			t.Fatalf("old credential not revoked after draining: %v", revoked)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRealPostgres_PoolCancelReachesTheBoundConnection(t *testing.T) {
	f := newPoolFixture(t, 2, time.Hour, PoolOptions{})
	conn := f.connect(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := conn.Exec(ctx, "SELECT pg_sleep(10)"); err == nil {
		t.Fatal("sleep was not cancelled")
	}
	if waited := time.Since(started); waited > 4*time.Second {
		t.Fatalf("cancel took %v", waited)
	}
	fresh := f.connect(t, nil)
	if _, err := fresh.Exec(context.Background(), "SELECT 1"); err != nil {
		t.Fatalf("pool unusable after a cancel: %v", err)
	}
	_ = strconv.Itoa
}

// Pipelined batches, COPY, a failed transaction and LISTEN all work through
// the pool, and a failed batch leaves prepared statements usable.
func TestRealPostgres_PoolProtocolSurface(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{SessionShare: 1})
	ctx := context.Background()
	table := f.env.table()
	a, b := f.connect(t, nil), f.connect(t, nil)
	batch := &pgx.Batch{}
	for i := range 50 {
		batch.Queue("SELECT $1::int * 2", i)
	}
	results := a.SendBatch(ctx, batch)
	for i := range 50 {
		var v int
		if err := results.QueryRow().Scan(&v); err != nil || v != i*2 {
			t.Fatalf("batch item %d = %d: %v", i, v, err)
		}
	}
	if err := results.Close(); err != nil {
		t.Fatal(err)
	}
	copied, err := b.CopyFrom(ctx, pgx.Identifier{table}, []string{"worker", "n"}, pgx.CopyFromRows([][]any{{7, 1}, {7, 2}, {7, 3}}))
	if err != nil || copied != 3 {
		t.Fatalf("COPY through the pool: %d %v", copied, err)
	}
	tx, err := a.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT 1/0"); err == nil {
		t.Fatal("division by zero succeeded")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback after a failed statement: %v", err)
	}
	var v int
	if err := a.QueryRow(ctx, "SELECT $1::int * 2", 21).Scan(&v); err != nil || v != 42 {
		t.Fatalf("prepared statement after a failure: %d %v", v, err)
	}
	if _, err := b.Exec(ctx, "LISTEN pool_test_channel"); err != nil {
		t.Fatalf("LISTEN pins the session: %v", err)
	}
	if _, err := f.env.admin.Exec(ctx, "NOTIFY pool_test_channel, 'hello'"); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	note, err := b.WaitForNotification(waitCtx)
	if err != nil || note.Payload != "hello" {
		t.Fatalf("notification through a pinned session: %v %v", note, err)
	}
}

// A server connection that dies while idle is replaced, not handed to a client.
func TestRealPostgres_PoolReplacesDeadIdleConnections(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	ctx := context.Background()
	a := f.connect(t, nil)
	if _, err := a.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	f.broker.pools.mu.Lock()
	for _, pool := range f.broker.pools.pools {
		for _, conn := range pool.idle {
			conn.idleAt = time.Now().Add(-time.Minute) // as if idle for a while
		}
	}
	f.broker.pools.mu.Unlock()
	for _, role := range f.env.roles {
		f.env.exec(fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s'", role))
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := a.Exec(ctx, "SELECT 2"); err != nil {
		t.Fatalf("dead idle connection handed to a client: %v", err)
	}
}

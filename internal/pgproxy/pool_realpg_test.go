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
	"os/exec"
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

func (m *rotatingMinter) Mint(_ context.Context, _ AgentScope, _ *DatabaseService) (*Lease, error) {
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
	// Both refusals are audited, so a saturated budget can raise an alert.
	outcomes := map[string]int{}
	for _, e := range f.audit.recorded() {
		if e.Event == auditchain.EventDenied {
			outcomes[e.Outcome]++
		}
	}
	if outcomes["pinned_share"] != 1 || outcomes["pool_budget"] != 1 {
		t.Fatalf("refusals audited as %v", outcomes)
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
	// Check-in finishes after the client has its answer; wait for it.
	waitFor(t, 2*time.Second, func() bool { _, idle := f.broker.pools.stats(f.env.upAddr); return idle == 1 }, "connection checked in")
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

// The classifier cannot see inside functions. A function that sets a session
// setting, creates a temp table or takes a session advisory lock passes as a
// plain SELECT; the check-in backstop finds the state, resets the connection
// and audits the catch, so the next client starts clean.
func TestRealPostgres_PoolCheckInCatchesStateTheClassifierMissed(t *testing.T) {
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	ctx := context.Background()
	suffix := strings.TrimPrefix(f.env.roles[0], "pool_a_")
	schema := "other_" + suffix
	f.env.exec(fmt.Sprintf("CREATE FUNCTION %s.sneaky_path() RETURNS text LANGUAGE sql AS $$ SELECT set_config('search_path', '%s', false) $$", schema, schema))
	f.env.exec(fmt.Sprintf("CREATE FUNCTION %s.sneaky_temp() RETURNS void LANGUAGE plpgsql AS $$ BEGIN CREATE TEMP TABLE IF NOT EXISTS sneaky (id int); END $$", schema))
	f.env.exec(fmt.Sprintf("CREATE FUNCTION %s.sneaky_lock() RETURNS void LANGUAGE sql AS $$ SELECT pg_advisory_lock(4242) $$", schema))
	for _, role := range f.env.roles {
		f.env.exec(fmt.Sprintf("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %s TO %s", schema, role))
	}
	leaks := func() int {
		n := 0
		for _, e := range f.audit.recorded() {
			if e.Event == auditchain.EventStateLeak {
				n++
			}
		}
		return n
	}
	for i, call := range []string{"sneaky_path()", "sneaky_temp()", "sneaky_lock()"} {
		a := f.connect(t, nil)
		if _, err := a.Exec(ctx, "SELECT "+schema+"."+call); err != nil {
			t.Fatalf("%s: %v", call, err)
		}
		waitFor(t, 3*time.Second, func() bool { return leaks() == i+1 }, "state leak caught for "+call)
		b := f.connect(t, nil) // budget 1: the same server connection
		var path string
		var temps, locks int
		if err := b.QueryRow(ctx, "SELECT current_setting('search_path'), (SELECT count(*) FROM pg_class WHERE relnamespace = pg_my_temp_schema()),"+
			" (SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid())").Scan(&path, &temps, &locks); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(path, schema) || temps != 0 || locks != 0 {
			t.Fatalf("after %s the next client saw search_path=%q temps=%d advisory locks=%d", call, path, temps, locks)
		}
	}
	// SET LOCAL ends with its transaction: not a leak.
	a := f.connect(t, nil)
	tx, err := a.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL TimeZone = 'Asia/Tokyo'"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if leaks() != 3 {
		t.Fatalf("SET LOCAL was reported as a leak: %d", leaks())
	}
}

// Two entitlement tiers are two bindings with two database roles. Their
// clients never share a server connection: every transaction runs as its
// own tier's role, even with both tiers busy on one small shared budget.
func TestRealPostgres_PoolKeySeparatesEntitlementTiers(t *testing.T) {
	env := newPoolEnv(t)
	minter := &tierMinter{env: env}
	tiers := map[string]*DatabaseService{
		"tier1": {Name: "tier1", Addr: env.upAddr, Database: env.db, Mount: "database", Role: "t1-readonly", SSLMode: "disable", MaxConns: 2},
		"tier2": {Name: "tier2", Addr: env.upAddr, Database: env.db, Mount: "database", Role: "t2-readwrite", SSLMode: "disable", MaxConns: 2},
	}
	b, addr := startBroker(t, Options{
		Auth: &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-uid-1", Pool: "cursor"}},
		Databases: resolverFunc(func(_ context.Context, _ AgentScope, requested string) (*DatabaseService, error) {
			if svc, ok := tiers[requested]; ok {
				copied := *svc
				return &copied, nil
			}
			return nil, errors.New("unknown")
		}),
		Leases: minter, MaxConns: 500, MaxLeasesPerActor: 500, Pool: &PoolOptions{QueueFactor: 20},
	})
	f := &poolFixture{env: env, broker: b, addr: addr}
	want := map[string]string{"tier1": env.roles[0], "tier2": env.roles[1]}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		tier := []string{"tier1", "tier2"}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := f.connectTo(t, tier)
			for range 15 {
				var user string
				if err := conn.QueryRow(context.Background(), "SELECT current_user").Scan(&user); err != nil {
					errs <- err
					return
				}
				if user != want[tier] {
					errs <- fmt.Errorf("a %s client ran as %s", tier, user)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	b.pools.mu.Lock()
	keys := len(b.pools.pools)
	b.pools.mu.Unlock()
	if keys != 2 {
		t.Fatalf("%d pool keys, want one per tier", keys)
	}
}

type tierMinter struct {
	env *poolEnv
	mu  sync.Mutex
	n   int
}

func (m *tierMinter) Mint(_ context.Context, _ AgentScope, svc *DatabaseService) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	role := m.env.roles[0]
	if svc.Role == "t2-readwrite" {
		role = m.env.roles[1]
	}
	return &Lease{ID: fmt.Sprintf("tier-lease-%d", m.n), Username: role, Password: m.env.pw, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (m *tierMinter) Renew(context.Context, string, time.Duration) (time.Time, error) {
	return time.Time{}, errors.New("unused")
}
func (m *tierMinter) Revoke(context.Context, string) error { return nil }

func (f *poolFixture) connectTo(t *testing.T, database string) *pgx.Conn {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	conn, err := pgx.Connect(context.Background(), fmt.Sprintf("host=%s port=%s user=workload password=agent-token dbname=%s sslmode=disable", host, port, database))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// libpq is what psycopg drives, so libpq's default startup packet is
// psycopg's: user, database, application_name (psql sets one) and the
// locale's client_encoding, which is SQL_ASCII under the C locale. Requires
// AV_TEST_PSQL, a psql binary.
func TestRealPostgres_PoolLibpqDefaultStartup(t *testing.T) {
	psql := os.Getenv("AV_TEST_PSQL")
	if psql == "" {
		t.Skip("set AV_TEST_PSQL to a psql binary")
	}
	f := newPoolFixture(t, 1, time.Hour, PoolOptions{})
	host, port, _ := net.SplitHostPort(f.addr)
	for _, locale := range []string{"en_US.UTF-8", "C"} {
		cmd := exec.Command(psql, fmt.Sprintf("host=%s port=%s user=workload dbname=core sslmode=disable", host, port), "-At", "-c",
			"SELECT current_setting('client_encoding') || '|' || (SELECT count(*) FROM generate_series(1, 3))")
		cmd.Env = []string{"PGPASSWORD=agent-token", "LC_ALL=" + locale, "LANG=" + locale, "PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("libpq with LC_ALL=%s: %v: %s", locale, err, out)
		}
		if got := strings.TrimSpace(string(out)); !strings.HasSuffix(got, "|3") {
			t.Fatalf("libpq with LC_ALL=%s answered %q", locale, got)
		}
	}
}

// node-postgres 8.x sends only user and database by default and uses unnamed
// statements with parameters. Requires AV_TEST_NODE_PG_MODULES, a
// node_modules directory containing pg.
func TestRealPostgres_PoolNodePgDefaultStartup(t *testing.T) {
	modules := os.Getenv("AV_TEST_NODE_PG_MODULES")
	if modules == "" {
		t.Skip("set AV_TEST_NODE_PG_MODULES")
	}
	f := newPoolFixture(t, 2, time.Hour, PoolOptions{QueueFactor: 10})
	host, port, _ := net.SplitHostPort(f.addr)
	script := `const { Client } = require('pg');
(async () => {
  const clients = await Promise.all([0,1,2,3,4].map(async () => { const c = new Client({ host: process.argv[1], port: +process.argv[2], user: 'workload', password: 'agent-token', database: 'core' }); await c.connect(); return c; }));
  const sums = await Promise.all(clients.map(async (c, i) => { await c.query('BEGIN'); const r = await c.query('SELECT $1::int + $2::int AS s', [i, 10]); await c.query('COMMIT'); return r.rows[0].s; }));
  await Promise.all(clients.map(c => c.end()));
  console.log(JSON.stringify(sums));
})().catch(e => { console.error(e.message); process.exit(1); });`
	cmd := exec.Command("node", "-e", script, host, port)
	cmd.Env = append(os.Environ(), "NODE_PATH="+modules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node pg: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "[10,11,12,13,14]" {
		t.Fatalf("node pg answered %s", got)
	}
}

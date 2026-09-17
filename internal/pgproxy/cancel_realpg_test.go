//go:build realpg && realvault

package pgproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// Runtime identity and transport isolation are separate acceptance checks.
// This fixture uses real Vault leases and PostgreSQL query cancellation.
func TestRealPostgres_TwoSessionCancellationIsolation(t *testing.T) {
	client, admin, svc := realDurableInputs(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	minter := newDurableForTest(t, client, st)
	broker, addr := startBroker(t, Options{
		Leases: minter,
		Auth: authFunc(func(_ context.Context, token, _ string) (*AgentScope, error) {
			if token != "caller-a" && token != "caller-b" {
				return nil, errors.New("unknown fixture caller")
			}
			return &AgentScope{VaultID: "vault", ActorID: token, WorkloadID: token}, nil
		}),
		Databases: &fakeResolver{svc: svc},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connect := func(caller string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig("postgres://" + addr + "/durable?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = "agent", caller
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	a, b := connect("caller-a"), connect("caller-b")
	var pidA, pidB uint32
	var roleA, roleB string
	if err := a.QueryRow(ctx, "SELECT pg_backend_pid(), current_user").Scan(&pidA, &roleA); err != nil {
		t.Fatal(err)
	}
	if err := b.QueryRow(ctx, "SELECT pg_backend_pid(), current_user").Scan(&pidB, &roleB); err != nil {
		t.Fatal(err)
	}
	if pidA == pidB || roleA == roleB {
		t.Fatal("fixture did not create distinct sessions and credentials")
	}
	keyA := pgproto3.CancelRequest{ProcessID: a.PgConn().PID(), SecretKey: append([]byte(nil), a.PgConn().SecretKey()...)}
	keyB := pgproto3.CancelRequest{ProcessID: b.PgConn().PID(), SecretKey: append([]byte(nil), b.PgConn().SecretKey()...)}
	send := func(request pgproto3.CancelRequest) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		packet, err := request.Encode(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatal("cancellation exchange did not complete", err)
		}
	}
	running := func(pid uint32) bool {
		var active bool
		err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='active' AND wait_event='PgSleep')", pid).Scan(&active)
		return err == nil && active
	}
	run := func(conn *pgx.Conn, query string) <-chan error {
		done := make(chan error, 1)
		go func() { _, err := conn.Exec(ctx, query); done <- err }()
		return done
	}
	aDone, bDone := run(a, "SELECT pg_sleep(10)"), run(b, "SELECT pg_sleep(1.5)")
	waitFor(t, time.Second, func() bool { return running(pidA) && running(pidB) }, "both queries must be active")
	send(pgproto3.CancelRequest{ProcessID: keyA.ProcessID, SecretKey: keyB.SecretKey})
	send(pgproto3.CancelRequest{ProcessID: keyB.ProcessID, SecretKey: keyA.SecretKey})
	if !running(pidA) || !running(pidB) {
		t.Fatal("mixed session capabilities interrupted a query")
	}
	send(keyA)
	select {
	case err := <-aDone:
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
			t.Fatal("correct capability did not cancel its query", err)
		}
	case <-ctx.Done():
		t.Fatal("query A did not stop")
	}
	if err := <-bDone; err != nil {
		t.Fatal("query B was interrupted", err)
	}
	if _, err := a.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal("cancel unnecessarily closed session A", err)
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		return broker.cancellations[cancelKey(keyA.ProcessID, keyA.SecretKey)] == nil
	}, "closed session capability remained registered")
	assertDatabaseRemoved(t, admin, roleA)
	bDone = run(b, "SELECT pg_sleep(0.5)")
	waitFor(t, time.Second, func() bool { return running(pidB) }, "query B did not restart")
	send(keyA)
	if err := <-bDone; err != nil {
		t.Fatal("expired capability interrupted session B", err)
	}
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRemoved(t, admin, roleB)
	t.Log("mixed capabilities denied; valid cancellation stopped only A; B completed; closed capability replay harmless; residual roles=0 sessions=0; caller identity synthetic")
}

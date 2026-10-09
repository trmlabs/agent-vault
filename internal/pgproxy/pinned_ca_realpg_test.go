//go:build realpg

// A real PostgreSQL serving TLS with a certificate no public root signs, the
// way Citus and AlloyDB do. Run against one started with ssl=on:
//
//	AV_TEST_PG_TLS_UPSTREAM=127.0.0.1:5434 \
//	AV_TEST_PG_TLS_ADMIN='postgres://postgres:test-only-pw@127.0.0.1:5434/postgres?sslmode=require' \
//	AV_TEST_PG_TLS_CA=/path/to/pinned.pem \
//	AV_TEST_PG_TLS_SERVER_NAME=db.pinned.test \
//	go test -tags realpg ./internal/pgproxy/ -run RealPostgresPinnedCA -v
//
// AV_TEST_PG_TLS_CA is the CA that signed the server's certificate, or the
// server's self-signed certificate itself; AV_TEST_PG_TLS_SERVER_NAME is the
// name the certificate carries, empty for a self-signed one with none.
package pgproxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestRealPostgresPinnedCA(t *testing.T) {
	upstream := os.Getenv("AV_TEST_PG_TLS_UPSTREAM")
	adminDSN := os.Getenv("AV_TEST_PG_TLS_ADMIN")
	caFile := os.Getenv("AV_TEST_PG_TLS_CA")
	if upstream == "" || adminDSN == "" || caFile == "" {
		t.Skip("set AV_TEST_PG_TLS_UPSTREAM, AV_TEST_PG_TLS_ADMIN, AV_TEST_PG_TLS_CA to run the pinned-CA test")
	}
	pin, err := os.ReadFile(caFile) //nolint:gosec // a path the person running the test names
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	const roleName = "av_it_pinned"
	const rolePassword = "it-pinned-pw"
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+roleName)
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, roleName, rolePassword)); err != nil {
		t.Fatalf("create role: %v", err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+roleName) }()
	lease := &Lease{ID: "it-pinned", Username: roleName, Password: rolePassword, ExpiresAt: time.Now().Add(time.Hour)}
	dial := (&net.Dialer{}).DialContext

	svc := &DatabaseService{Name: "pinned", Addr: upstream, Database: "postgres", SSLMode: "verify-full",
		CA: string(pin), ServerName: os.Getenv("AV_TEST_PG_TLS_SERVER_NAME")}
	sess, err := connectUpstream(ctx, dial, svc, lease, nil)
	if err != nil {
		t.Fatalf("pinned connection: %v", err)
	}
	var ssl bool
	if err := admin.QueryRow(ctx, `SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename = $1`, roleName).Scan(&ssl); err != nil || !ssl {
		t.Fatalf("the broker's session is not on TLS: ssl=%v %v", ssl, err)
	}
	_ = sess.conn.Close()

	// The bundled roots do not trust it, and neither does another pin.
	unpinned := *svc
	unpinned.CA = ""
	if _, err := connectUpstream(ctx, dial, &unpinned, lease, nil); !handshakeRefused(err) {
		t.Fatalf("unpinned connection: %v", err)
	}
	other := *svc
	other.CA = testCA(t, "other-ca").pem()
	if _, err := connectUpstream(ctx, dial, &other, lease, nil); !handshakeRefused(err) {
		t.Fatalf("connection pinned to another CA: %v", err)
	}
}

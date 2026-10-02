//go:build realvault && realpg

package pgproxy

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/jackc/pgx/v5"
)

func fleetJournal(t *testing.T) *store.SQLStore {
	t.Helper()
	url := os.Getenv("AV_TEST_STORE_PG_URL")
	if url == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	opened, err := store.OpenStore(store.StoreConfig{DatabaseURL: url})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened.(*store.SQLStore)
}

func TestRealVault_FleetReplicaHelper(t *testing.T) {
	if os.Getenv("AV_FLEET_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	ctx := context.Background()
	client, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewDurableLeaseMinter(ctx, client, fleetJournal(t), DurableLeaseOptions{Replica: "replica-1"})
	if err != nil {
		t.Fatal(err)
	}
	role := os.Getenv("AV_TEST_VAULT_ROLE")
	if role == "" {
		role = "readonly"
	}
	svc := &DatabaseService{Name: "durable", Addr: os.Getenv("AV_TEST_PG_UPSTREAM"), Database: os.Getenv("AV_TEST_PG_DB"), Mount: "database", Role: role, SSLMode: "disable"}
	lease, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	conn := connectDurableLease(t, svc, lease)
	// The parent test supplies this path inside its private temporary directory.
	// #nosec G703
	if err = os.WriteFile(os.Getenv("AV_FLEET_READY"), []byte(lease.Username+"\n"+strconv.FormatInt(lease.ExpiresAt.Unix(), 10)), 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, "SELECT pg_sleep(120)")
	select {}
}

// Two replicas share a PostgreSQL journal with production timings. Replica 1
// is SIGKILLed mid-query. Replica 0 waits for the dead owner row to expire by
// the database clock, then claims and revokes: the Vault-created role and its
// session are gone within 40 seconds of the kill, and never before the row
// could have expired.
func TestRealVault_FleetSurvivorRevokesCrashedReplica(t *testing.T) {
	client, admin, _ := realDurableInputs(t)
	journal := fleetJournal(t)
	ctx := context.Background()
	reset, err := pgx.Connect(ctx, os.Getenv("AV_TEST_STORE_PG_URL"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"database_cleanup", "database_cleanup_replica", "broker_sessions"} {
		if _, err := reset.Exec(ctx, "DELETE FROM "+table); err != nil { // #nosec G202 -- fixed table names
			t.Fatal(err)
		}
	}
	_ = reset.Close(ctx)
	survivor, err := NewDurableLeaseMinter(ctx, client, journal, DurableLeaseOptions{Replica: "replica-0"})
	if err != nil {
		t.Fatal(err)
	}
	defer survivor.Close(ctx)

	ready := filepath.Join(t.TempDir(), "ready")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestRealVault_FleetReplicaHelper$")
	child.Env = append(os.Environ(), "AV_FLEET_CHILD=1", "AV_FLEET_READY="+ready)
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	var username string
	var expires int64
	waitWithin(t, 15*time.Second, "replica 1 session active", func() bool {
		data, err := os.ReadFile(ready)
		if err != nil {
			return false
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return false
		}
		username = fields[0]
		expires, _ = strconv.ParseInt(fields[1], 10, 64)
		var active int
		_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND state='active'", username).Scan(&active)
		return active == 1
	})
	if time.Until(time.Unix(expires, 0)) < time.Minute {
		t.Skip("the database role's lease must outlive the takeover; set AV_TEST_VAULT_ROLE to a role with a TTL of a minute or more")
	}
	if live := survivor.LiveReplicas(); live < 1 {
		t.Fatalf("live replicas = %d", live)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	killed := time.Now()
	gone := func() bool {
		var roles, sessions int
		_ = admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1), (SELECT count(*) FROM pg_stat_activity WHERE usename=$1)`, username).Scan(&roles, &sessions)
		return roles == 0 && sessions == 0
	}
	waitWithin(t, 45*time.Second, "survivor revoked the crashed replica's role", gone)
	took := time.Since(killed)
	if took > 40*time.Second {
		t.Fatalf("survivor revoked %s after the kill, want at most 40s", took.Round(100*time.Millisecond))
	}
	// The dead row was renewed at most 5s before the kill and lives 30s.
	if took < 20*time.Second {
		t.Fatalf("revoked %s after the kill, before the dead owner could have expired", took.Round(100*time.Millisecond))
	}
	records, err := journal.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 0 {
		t.Fatalf("journal not empty after takeover: %d %v", len(records), err)
	}
	t.Logf("SIGKILLed replica's role and session revoked by the survivor %s after the kill; residual roles=0 sessions=0", took.Round(100*time.Millisecond))
}

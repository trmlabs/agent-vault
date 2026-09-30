//go:build realcombined

package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
)

// verifyCombinedExecutableRestart exercises the actual CLI against the same
// persisted store after the component-level recovery. The optional explicit
// binary is built by the disposable runner, never taken from PATH.
func verifyCombinedExecutableRestart(t *testing.T, s combinedRecovery, token string) {
	t.Helper()
	binary := os.Getenv("AV_TEST_EXECUTABLE")
	if binary == "" {
		t.Log("executable recovery not requested")
		return
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".agent-vault")
	must := func(err error, stage string) {
		t.Helper()
		if err != nil {
			t.Fatal(stage)
		}
	}
	must(os.Mkdir(dir, 0700), "private home")
	must(os.Rename(s.storePath, filepath.Join(dir, "agent-vault.db")), "move closed fixture store")
	identity, err := json.Marshal(s.identityConfig)
	must(err, "encode identity")
	identityFile := filepath.Join(home, "identity.json")
	must(os.WriteFile(identityFile, identity, 0600), "write identity")
	rootsFile := filepath.Join(home, "roots.pem")
	must(os.WriteFile(rootsFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.destination.Certificate().Raw}), 0600), "write public trust")
	services, _ := json.Marshal(map[string]any{"combined": []map[string]any{{"name": "database", "upstream": os.Getenv("AV_TEST_PG_UPSTREAM"), "database": os.Getenv("AV_TEST_PG_DB"), "mount": "database", "role": "readonly", "sslmode": "disable"}}})
	port := func() string {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		must(e, "allocate loopback port")
		p := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
		_ = l.Close()
		return p
	}
	management, proxyPort, pgPort, observerPort := port(), port(), port(), port()
	observerBytes, err := os.ReadFile(os.Getenv("AV_TEST_OBSERVER_PROOF"))
	must(err, "read disposable observer proof")
	observerProof := strings.TrimSpace(string(observerBytes))
	var command *exec.Cmd
	var logs bytes.Buffer
	var done chan error
	stop := func() {
		if command == nil {
			return
		}
		_ = command.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		command = nil
	}
	defer stop()
	start := func(auth string) {
		command = exec.Command(binary, "server", "--host", "127.0.0.1", "--port", management, "--mitm-port", proxyPort, "--postgres-port", pgPort)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "AGENT_VAULT_MASTER_PASSWORD=disposable-fixture-master-password", "VAULT_ADDR=" + os.Getenv("VAULT_ADDR"), "VAULT_TOKEN=" + auth, "AGENT_VAULT_CREDENTIAL_PROXY=true", "AGENT_VAULT_DB_BROKER=true", "AGENT_VAULT_WORKLOAD_IDENTITY_FILE=" + identityFile, "AGENT_VAULT_DB_SERVICES=" + string(services), "AGENT_VAULT_NETWORK_ALLOWLIST=127.0.0.1/32,::1/128", "SSL_CERT_FILE=" + rootsFile, "DO_NOT_TRACK=1"}
		command.Env = append(command.Env, "AGENT_VAULT_CLEANUP_OBSERVER_FILE="+os.Getenv("AV_TEST_OBSERVER_CONFIG"), "AGENT_VAULT_CLEANUP_OBSERVER_PORT="+observerPort)
		command.Stdout, command.Stderr = &logs, &logs
		must(command.Start(), "start actual executable")
		done = make(chan error, 1)
		go func() { done <- command.Wait() }()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				command = nil
				t.Fatal("actual executable exited before ready")
			default:
			}
			c, e := net.DialTimeout("tcp", "127.0.0.1:"+pgPort, 100*time.Millisecond)
			if e == nil {
				_ = c.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("actual executable startup deadline")
	}
	httpRequest := func(want bool) {
		ca, err := os.ReadFile(filepath.Join(home, ".agent-vault", "ca", "ca.crt.pem"))
		must(err, "read public interception CA")
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("invalid public interception CA")
		}
		transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:" + proxyPort}), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer " + s.proof}}}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequest(http.MethodGet, s.destination.URL+"/approved", nil)
		must(err, "build actual proxy request")
		request.Header.Set("Authorization", "Bearer __vault_API_KEY__")
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			if want {
				t.Fatal("actual executable HTTP request failed")
			}
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		must(err, "read bounded proxy result")
		if want && (response.StatusCode != 200 || string(body) != "approved-output") {
			t.Fatalf("actual executable HTTP denied: status %d", response.StatusCode)
		}
		if !want && response.StatusCode < 400 {
			t.Fatal("revoked parent still forwarded HTTP")
		}
	}
	var roles []string
	database := func(want bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg, e := pgx.ParseConfig("postgres://127.0.0.1:" + pgPort + "/database?sslmode=disable")
		must(e, "client config")
		cfg.User = "workload"
		cfg.Password = s.proof
		cfg.ConnectTimeout = 3 * time.Second
		c, e := pgx.ConnectConfig(ctx, cfg)
		if !want {
			if e == nil {
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = c.Close(closeCtx)
				closeCancel()
				t.Fatal("revoked parent admitted database")
			}
			return
		}
		must(e, "actual executable database connection")
		defer func() {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer closeCancel()
			_ = c.Close(closeCtx)
		}()
		var answer int
		must(c.QueryRow(ctx, "SELECT 1").Scan(&answer), "actual executable database read")
		if answer != 1 {
			t.Fatal("unexpected database result")
		}
		var role string
		must(c.QueryRow(ctx, "SELECT current_user").Scan(&role), "record disposable database role")
		roles = append(roles, role)
	}
	observe := func(proof, path string) (int, bool) {
		request, e := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+observerPort+path, nil)
		must(e, "observer request")
		request.Header.Set("Authorization", "Bearer "+proof)
		response, e := (&http.Client{Timeout: 6 * time.Second}).Do(request)
		must(e, "actual observer response")
		defer response.Body.Close()
		return response.StatusCode, executableCleanupReady(response.Body)
	}
	ready := func() {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if code, healthy := observe(observerProof, "/v1/runtime/cleanup-status"); code == 200 && healthy {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("actual observer never became healthy")
	}
	start(token)
	ready()
	if code, _ := observe(s.proof, "/v1/runtime/cleanup-status"); code != 401 {
		t.Fatal("proxy proof admitted to observer")
	}
	if code, _ := observe(observerProof, "/v1/auth/register"); code != 404 {
		t.Fatal("observer exposes owner management")
	}
	httpRequest(true)
	database(true)
	_, e := s.vaultAdmin.Logical().WriteWithContext(s.ctx, "auth/token/revoke", map[string]any{"token": token})
	must(e, "revoke scoped parent")
	httpRequest(false)
	database(false)
	if code, _ := observe(observerProof, "/v1/runtime/cleanup-status"); code != 503 {
		t.Fatal("revoked parent reported healthy observer")
	}
	stop()
	if strings.Contains(logs.String(), token) {
		t.Fatal("broker token appeared in executable log")
	}
	parent, e := s.vaultAdmin.Auth().Token().CreateWithContext(s.ctx, &vaultapi.TokenCreateRequest{Policies: []string{s.policy, "agent-vault-database-parent", hashicorp.DatabaseCredentialPolicyName("database", "readonly")}, TTL: "2m"})
	must(e, "replacement parent")
	defer s.vaultAdmin.Auth().Token().RevokeAccessorWithContext(context.Background(), parent.Auth.Accessor)
	start(parent.Auth.ClientToken)
	ready()
	httpRequest(true)
	database(true)
	stop()
	if strings.Contains(logs.String(), parent.Auth.ClientToken) {
		t.Fatal("replacement token appeared in executable log")
	}
	cleanupDeadline := time.Now().Add(10 * time.Second)
	for _, role := range roles {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var count int
			err := s.dbAdmin.QueryRow(ctx, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname=$1)+(SELECT count(*) FROM pg_stat_activity WHERE usename=$1)", role).Scan(&count)
			cancel()
			must(err, "independent database cleanup observation")
			if count == 0 {
				break
			}
			if time.Now().After(cleanupDeadline) {
				t.Fatal("actual executable left database role or session")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Log("actual compiled CLI restored HTTP request-time reads and real PostgreSQL access from the same persisted store with replacement parent authentication; Python manager and five-database Cursor workflow are not exercised")
}

func executableCleanupReady(body io.Reader) bool {
	var status struct {
		Status  string `json:"status"`
		Active  *int   `json:"activeConnections"`
		Pending *int   `json:"unfinishedCleanup"`
		Unknown *int   `json:"unknownCleanup"`
	}
	decoded := json.NewDecoder(io.LimitReader(body, 4096)).Decode(&status) == nil
	return decoded && status.Status == "ready" && status.Active != nil && status.Pending != nil && status.Unknown != nil && *status.Active == 0 && *status.Pending == 0 && *status.Unknown == 0
}

func TestExecutableCleanupReceiptRequiresEveryZeroCount(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"complete", `{"status":"ready","activeConnections":0,"unfinishedCleanup":0,"unknownCleanup":0}`, true},
		{"missing", `{"status":"ready","activeConnections":0,"unfinishedCleanup":0}`, false},
		{"pending", `{"status":"ready","activeConnections":0,"unfinishedCleanup":1,"unknownCleanup":0}`, false},
		{"null", `{"status":"ready","activeConnections":null,"unfinishedCleanup":0,"unknownCleanup":0}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if executableCleanupReady(strings.NewReader(tc.body)) != tc.want {
				t.Fatal("cleanup readiness classification differs")
			}
		})
	}
}

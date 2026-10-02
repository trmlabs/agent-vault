package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
)

// shutdownVault answers a JWT login and records revocations.
type shutdownVault struct {
	mu      sync.Mutex
	revoked []string
}

func (v *shutdownVault) revokedTokens() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.revoked...)
}

func (v *shutdownVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/auth/gatehouse/login":
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "synthetic-parent-login", "lease_duration": 600, "renewable": true}})
	case "/v1/auth/token/lookup-self":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"explicit_max_ttl": 3600}})
	case "/v1/auth/token/revoke-self":
		v.mu.Lock()
		v.revoked = append(v.revoked, r.Header.Get("X-Vault-Token"))
		v.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// vaultOrderProbe is the database cleanup: it records whether the Vault login
// was already revoked when it ran, since it revokes sessions with it.
type vaultOrderProbe struct {
	vault        *shutdownVault
	revokedFirst bool
	calls        int
}

func (p *vaultOrderProbe) Close(context.Context) error {
	p.calls++
	p.revokedFirst = len(p.vault.revokedTokens()) > 0
	return nil
}

// A graceful stop revokes the broker's Vault login, after the database
// cleanup that still needs it, and before Start returns.
func TestGracefulShutdownRevokesVaultLogins(t *testing.T) {
	vault := &shutdownVault{}
	vaultSrv := httptest.NewServer(vault)
	t.Cleanup(vaultSrv.Close)
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte("header.payload.signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"HOME": t.TempDir(), "VAULT_ADDR": vaultSrv.URL, "VAULT_TOKEN": "", "VAULT_ROLE_ID": "", "VAULT_SECRET_ID": "",
		"VAULT_JWT_MOUNT": "gatehouse", "VAULT_JWT_ROLE": "broker", "VAULT_JWT_TOKEN_FILE": jwtFile} {
		t.Setenv(k, v)
	}
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	s.httpServer.Addr = addr
	s.AttachHashicorp(client)
	probe := &vaultOrderProbe{vault: vault}
	s.AttachDatabaseCleanup(probe)
	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	// The management listener serves only once the signal handler is in place.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never listened")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("graceful shutdown did not finish")
	}
	if got := vault.revokedTokens(); len(got) != 1 || got[0] != "synthetic-parent-login" {
		t.Fatalf("revoked %v; want the broker's login", got)
	}
	if probe.calls != 1 || probe.revokedFirst {
		t.Fatalf("database cleanup ran %d times, after the Vault revoke: %v", probe.calls, probe.revokedFirst)
	}
}

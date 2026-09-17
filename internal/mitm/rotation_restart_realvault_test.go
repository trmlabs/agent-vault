//go:build realvault

package mitm

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
)

// This fixture starts its own disposable Vault. It never uses VAULT_ADDR or
// credentials from the caller's environment. Upstreams and SQLite are local.
func TestRealVault_RotationRestart(t *testing.T) {
	runVaultFreshnessFixture(t, false)
}

// TestRealVault_StrictHTTPProfile integrates real Vault, SQLite audit and the
// strict HTTP path. Its stored agent token isolates HTTP behavior; actual
// Kubernetes-issued proof is tested separately by workloadidentity.
func TestRealVault_StrictHTTPProfile(t *testing.T) { runVaultFreshnessFixture(t, true, true) }

func runVaultFreshnessFixture(t *testing.T, strict bool, profile ...bool) {
	release := len(profile) > 0 && profile[0]
	marker := "__REFERENCE_KEY__"
	missingStatus := 502
	if release {
		marker = "__vault_REFERENCE_KEY__"
		missingStatus = 403
	}

	bin, err := exec.LookPath("vault")
	if err != nil {
		t.Fatal("realvault HTTP fixture requires the Vault binary")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	rootBytes := make([]byte, 32)
	if _, err := rand.Read(rootBytes); err != nil {
		t.Fatal(err)
	}
	root := hex.EncodeToString(rootBytes)
	cmd := exec.Command(bin, "server", "-dev", "-dev-listen-address="+address)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "VAULT_DEV_ROOT_TOKEN_ID=" + root, "VAULT_LOG_LEVEL=error"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start disposable Vault")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	config := vaultapi.DefaultConfig()
	config.Address = "http://" + address
	config.Timeout = time.Second
	admin, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatal("cannot configure fixture Vault client")
	}
	admin.SetToken(root)
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := admin.Logical().ReadWithContext(ctx, "auth/token/lookup-self")
		cancel()
		if err == nil {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("disposable Vault did not become ready")
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(secretBytes)
	ctx := context.Background()
	if _, err := admin.Logical().WriteWithContext(ctx, "secret/data/http-reference", map[string]interface{}{"data": map[string]interface{}{"REFERENCE_KEY": secret}}); err != nil {
		t.Fatal("fixture KV write failed")
	}
	t.Setenv("VAULT_ADDR", config.Address)
	t.Setenv("VAULT_TOKEN", root)
	t.Setenv("VAULT_NAMESPACE", "")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	hc, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal("production Vault client failed against disposable service")
	}

	for _, secure := range []bool{false, true} {
		if release && !secure {
			continue
		}
		mode := "forward"
		if secure {
			mode = "connect"
		}
		t.Run(mode, func(t *testing.T) {
			var expected atomic.Value
			expected.Store(secret)
			writeKey := func(value string) {
				t.Helper()
				if _, err := admin.Logical().WriteWithContext(ctx, "secret/data/http-reference", map[string]interface{}{"data": map[string]interface{}{"REFERENCE_KEY": value}}); err != nil {
					t.Fatal("fixture KV write failed")
				}
			}
			writeKey(secret)
			var calls atomic.Int32
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) {
					http.Error(w, "stale credential", 401)
					return
				}
				_, _ = io.WriteString(w, "approved")
			}))
			if secure {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			defer upstream.Close()
			path := filepath.Join(t.TempDir(), "rotation.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			v, err := st.CreateVault(ctx, "rotation")
			if err != nil {
				t.Fatal(err)
			}
			dek := make([]byte, 32)
			if _, err := rand.Read(dek); err != nil {
				t.Fatal(err)
			}
			if _, err := st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"http-reference","kv_version":2}`, PollIntervalSeconds: 60}); err != nil {
				t.Fatal(err)
			}
			refresh := func(wantSuccess bool) {
				t.Helper()
				row, err := st.GetVaultCredentialStore(ctx, v.ID)
				if err != nil || row == nil {
					t.Fatal("external store missing")
				}
				err = hashicorp.NewSyncer(st, hc, dek, slog.New(slog.DiscardHandler)).RefreshOnce(ctx, *row)
				if (err == nil) != wantSuccess {
					t.Fatalf("refresh success=%v want=%v", err == nil, wantSuccess)
				}
			}
			if !strict {
				refresh(true)
			}
			u, _ := url.Parse(upstream.URL)
			port, _ := strconv.Atoi(u.Port())
			service := broker.Service{Name: "read", Host: u.Hostname(), Port: &port, Path: "/approved", Auth: broker.Auth{Type: "bearer", Token: "REFERENCE_KEY"}}
			if strict {
				service.Auth = broker.Auth{Type: "passthrough"}
				service.Substitutions = []broker.Substitution{{Key: "REFERENCE_KEY", Placeholder: marker, In: []string{"header"}}}
			}
			services, err := json.Marshal([]broker.Service{service})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.SetBrokerConfig(ctx, v.ID, string(services)); err != nil {
				t.Fatal(err)
			}
			expires := time.Now().Add(time.Hour)
			agent, session, err := st.CreateAgentWithGrantsAndToken(ctx, "rotation-agent", "fixture", "no-access", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "proxy"}}, &expires)
			if err != nil {
				t.Fatal(err)
			}
			var client *http.Client
			var proxy *Proxy
			start := func() {
				provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, dek)
				if strict {
					provider.RequestSecrets = hashicorp.RequestResolver{Store: st, Fetcher: hc}
				}
				proxyURL, roots, p := setupProxy(t, brokercore.NewStoreSessionResolver(st), provider, func(o *Options) {
					if release {
						o.StrictCredentialProxy = true
						o.DurableAudit = requestlog.NewDurable(st)
					}
				})
				proxy = p
				if secure {
					pool := x509.NewCertPool()
					pool.AddCert(upstream.Certificate())
					proxy.upstream.TLSClientConfig.RootCAs = pool
				}
				client = newTrustingClient(proxyURL, url.UserPassword(session.ID, v.Name), roots)
				t.Cleanup(client.CloseIdleConnections)
			}
			start()
			request := func(t *testing.T, want int, requireReused bool) {
				t.Helper()
				var reused atomic.Bool
				trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
				req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", upstream.URL+"/approved", nil)
				if err != nil {
					t.Fatal(err)
				}
				if strict {
					req.Header.Set("Authorization", "Bearer "+marker)
				}
				resp, err := client.Do(req)
				if err != nil {
					// On a fresh HTTPS connection, a rejected CONNECT is surfaced
					// as a transport error rather than an HTTP response.
					if secure && !requireReused && ((want == 407 && strings.Contains(err.Error(), "Proxy Authentication Required")) || (release && want == 403 && strings.Contains(err.Error(), "Forbidden"))) {
						return
					}
					t.Fatal("fixture proxy request failed")
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != want {
					t.Fatalf("status=%d want=%d", resp.StatusCode, want)
				}
				if err != nil {
					t.Fatal(err)
				}
				if release {
					id := resp.Header.Get("X-Request-Id")
					row, err := st.GetProxyAudit(ctx, id)
					if err != nil || row.Outcome == "unknown" {
						t.Fatal("strict response lacks durable completed outcome")
					}
				}
				if requireReused && !reused.Load() {
					t.Fatal("rotation did not exercise reused connection")
				}
				if strings.Contains(string(body), secret) || strings.Contains(string(body), expected.Load().(string)) {
					t.Fatal("credential leaked into response")
				}
			}
			request(t, 200, false)
			rotatedBytes := make([]byte, 32)
			if _, err := rand.Read(rotatedBytes); err != nil {
				t.Fatal(err)
			}
			rotated := hex.EncodeToString(rotatedBytes)
			writeKey(rotated)
			expected.Store(rotated)
			if strict {
				t.Run("rotation_without_refresh", func(t *testing.T) { request(t, 200, true) })
			} else {
				request(t, 401, true) // Documents the existing stale-cache window.
			}
			if !strict {
				refresh(true)
			}
			request(t, 200, !strict)
			// A failed secret refresh retains the last good cached credential. This
			// is not a fail-closed freshness guarantee or a production outage test.
			if _, err := admin.Logical().DeleteWithContext(ctx, "secret/metadata/http-reference"); err != nil {
				t.Fatal("fixture KV deletion failed")
			}
			if !strict {
				refresh(false)
			}
			if strict {
				t.Run("deleted_secret_never_forwarded", func(t *testing.T) {
					before := calls.Load()
					defer func() {
						if calls.Load() != before {
							t.Error("request reached destination after Vault secret deletion")
						}
					}()
					request(t, missingStatus, false)
				})
				rows, err := st.ListCredentials(ctx, v.ID)
				if err != nil || len(rows) != 0 {
					t.Fatal("request-time resolution persisted credential values")
				}
				writeKey(rotated)
				request(t, 200, false)
			} else {
				request(t, 200, true) // Cache characterization only.

			}
			writeKey(rotated)

			restart := func() {
				t.Helper()
				client.CloseIdleConnections()
				stopCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if err := proxy.Shutdown(stopCtx); err != nil {
					t.Fatal(err)
				}
				if err := st.Close(); err != nil {
					t.Fatal(err)
				}
				st, err = store.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				start()
			}
			restart()
			request(t, 200, false) // Newly opened database and provider must resolve afresh.
			if strict {
				rows, err := st.ListCredentials(ctx, v.ID)
				if err != nil || len(rows) != 0 {
					t.Fatal("credential values persisted across restart")
				}
			}
			if err := st.RevokeAgent(ctx, agent.ID); err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			if release {
				request(t, 403, true)
			} else {
				request(t, 407, true)
			}
			restart()
			if release {
				request(t, 403, false)
			} else {
				request(t, 407, false)
			}
			if calls.Load() != before {
				t.Fatal("revoked identity reached upstream after restart")
			}
		})
	}
}

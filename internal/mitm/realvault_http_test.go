//go:build realvault

package mitm

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	"github.com/Infisical/agent-vault/internal/actionref"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
)

// This fixture starts its own disposable Vault. It never uses VAULT_ADDR or
// credentials from the caller's environment. Upstreams and SQLite are local.
func TestRealVault_HTTPAuthorization(t *testing.T) {
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

	t.Run("strict-fixed-query", func(t *testing.T) { testRealVaultFixedQuery(t, hc, admin) })
	for _, secure := range []bool{false, true} {
		mode := "forward"
		if secure {
			mode = "connect"
		}
		t.Run(mode+"/two-actor-isolation", func(t *testing.T) {
			testRealVaultActorCancellation(t, hc, secret, secure)
		})
		for _, change := range []string{"revoke", "expire", "remove-grant"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				st, err := store.Open(filepath.Join(t.TempDir(), "reference.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
				v, err := st.CreateVault(ctx, "reference")
				if err != nil {
					t.Fatal(err)
				}
				dek := make([]byte, 32)
				if _, err := rand.Read(dek); err != nil {
					t.Fatal(err)
				}
				_, err = st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"http-reference","kv_version":2}`, PollIntervalSeconds: 60})
				if err != nil {
					t.Fatal(err)
				}
				row, err := st.GetVaultCredentialStore(ctx, v.ID)
				if err != nil || row == nil {
					t.Fatal("external-store configuration missing")
				}
				if err := hashicorp.NewSyncer(st, hc, dek, slog.New(slog.DiscardHandler)).RefreshOnce(ctx, *row); err != nil {
					t.Fatal("real Vault synchronization failed")
				}
				var calls atomic.Int32
				var slow atomic.Bool
				started := make(chan struct{}, 8)
				stopped := make(chan struct{}, 8)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "Bearer "+secret {
						http.Error(w, "incorrect injected credential", http.StatusUnauthorized)
						return
					}
					if slow.Load() {
						started <- struct{}{}
						<-r.Context().Done()
						stopped <- struct{}{}
						return
					}
					_, _ = io.WriteString(w, `{"result":"approved-read","hidden":"fixture-only"}`)
				})
				upstream := httptest.NewUnstartedServer(handler)
				if secure {
					upstream.StartTLS()
				} else {
					upstream.Start()
				}
				t.Cleanup(upstream.Close)
				u, _ := url.Parse(upstream.URL)
				port, err := strconv.Atoi(u.Port())
				if err != nil {
					t.Fatal(err)
				}
				services, err := json.Marshal([]broker.Service{{Name: "read", Host: u.Hostname(), Port: &port, Path: "/approved", Auth: broker.Auth{Type: "bearer", Token: "REFERENCE_KEY"}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.SetBrokerConfig(ctx, v.ID, string(services)); err != nil {
					t.Fatal(err)
				}
				expiry := time.Now().Add(5 * time.Minute)
				agent, session, err := st.CreateAgentWithGrantsAndToken(ctx, "reference-agent", "fixture", "no-access", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "proxy"}}, &expiry)
				if err != nil {
					t.Fatal(err)
				}
				resolver := brokercore.NewStoreSessionResolver(st)
				var clock atomic.Int64
				clock.Store(time.Now().UnixNano())
				resolver.Now = func() time.Time { return time.Unix(0, clock.Load()) }
				provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, dek)
				proxyURL, roots, proxy := setupProxy(t, resolver, provider)
				if secure {
					pool := x509.NewCertPool()
					pool.AddCert(upstream.Certificate())
					proxy.upstream.TLSClientConfig.RootCAs = pool
				}
				client := newTrustingClient(proxyURL, url.UserPassword(session.ID, v.Name), roots)
				t.Cleanup(client.CloseIdleConnections)
				request := func(path string) (int, string, bool) {
					t.Helper()
					var reused atomic.Bool
					trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
					req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, upstream.URL+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal("proxy request failed before an HTTP assertion")
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						t.Fatal("cannot read proxy response")
					}
					if strings.Contains(string(body), secret) {
						t.Fatal("upstream credential appeared in fixture response")
					}
					return resp.StatusCode, string(body), reused.Load()
				}
				status, body, _ := request("/approved")
				if status != http.StatusOK || body != `{"result":"approved-read","hidden":"fixture-only"}` || calls.Load() != 1 {
					t.Fatal("positive control failed")
				}
				status, _, _ = request("/forbidden")
				if status != http.StatusForbidden || calls.Load() != 1 {
					t.Fatal("path restriction failed or reached upstream")
				}
				if change == "revoke" {
					for _, stopMode := range []string{"policy-revoked", "policy-unavailable", "identity-revoked", "deadline"} {
						t.Run("action/"+stopMode, func(t *testing.T) {
							var permission atomic.Int32
							gateway, err := actionref.New(actionref.Config{
								Client: client, Upstream: upstream.URL + "/approved", Fields: []string{"result"},
								Poll: 10 * time.Millisecond, LookupTimeout: 100 * time.Millisecond, MaxDuration: 300 * time.Millisecond,
								Verify: func(context.Context, string) (actionref.Identity, error) {
									if permission.Load() == 3 {
										return actionref.Identity{}, fmt.Errorf("fixture identity revoked")
									}
									return actionref.Identity{Actor: "fixture-actor", Run: "fixture-run", Expires: time.Now().Add(time.Minute)}, nil
								},
								Allow: func(context.Context, actionref.Identity) (bool, error) {
									if permission.Load() == 2 {
										return false, fmt.Errorf("fixture policy unavailable")
									}
									return permission.Load() == 0, nil
								},
							})
							if err != nil {
								t.Fatal(err)
							}
							requestAction := func() *httptest.ResponseRecorder {
								r := httptest.NewRequest("POST", "/actions/read", nil)
								r.Header.Set("Authorization", "Bearer synthetic-workload-proof")
								w := httptest.NewRecorder()
								gateway.ServeHTTP(w, r)
								return w
							}
							if w := requestAction(); w.Code != 200 || w.Body.String() != "{\"result\":\"approved-read\"}\n" {
								t.Fatal("action positive control or output filtering failed")
							}
							slow.Store(true)
							defer slow.Store(false)
							done := make(chan *httptest.ResponseRecorder, 1)
							go func() { done <- requestAction() }()
							select {
							case <-started:
							case <-time.After(2 * time.Second):
								t.Fatal("slow upstream not reached")
							}
							want := 403
							switch stopMode {
							case "policy-revoked":
								permission.Store(1)
							case "policy-unavailable":
								permission.Store(2)
							case "identity-revoked":
								permission.Store(3)
							case "deadline":
								want = 504
							}
							select {
							case w := <-done:
								if w.Code != want {
									t.Fatalf("stop status=%d want=%d", w.Code, want)
								}
							case <-time.After(2 * time.Second):
								t.Fatal("action did not stop")
							}
							select {
							case <-stopped:
							case <-time.After(2 * time.Second):
								t.Fatal("cancellation did not reach actual upstream")
							}
							before := calls.Load()
							if stopMode != "deadline" {
								newStatus := 403
								if stopMode == "identity-revoked" {
									newStatus = 401
								}
								if w := requestAction(); w.Code != newStatus || calls.Load() != before {
									t.Fatal("new action admitted after disablement")
								}
							}
						})
					}
					// Cancellation closes the tunnel; warm a new one for the reuse check.
					_, _, _ = request("/approved")
				}
				authorizedCalls := calls.Load()
				wantStatus, wantBody := http.StatusProxyAuthRequired, "invalid or expired session\n"
				switch change {
				case "revoke":
					if err := st.RevokeAgent(ctx, agent.ID); err != nil {
						t.Fatal(err)
					}
				case "expire":
					clock.Store(expiry.Add(time.Second).UnixNano())
				case "remove-grant":
					if err := st.RevokeVaultAccess(ctx, agent.ID, v.ID); err != nil {
						t.Fatal(err)
					}
					wantStatus, wantBody = http.StatusForbidden, "forbidden\n"
				}
				status, body, reused := request("/approved")
				if !reused {
					t.Fatal("negative check did not reuse the authenticated connection")
				}
				if status != wantStatus || body != wantBody || calls.Load() != authorizedCalls {
					t.Fatalf("authorization change not enforced: status=%d upstream_calls=%d", status, calls.Load())
				}
			})
		}
	}
}

//go:build realvault

package mitm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/actionref"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// These isolated action handlers share a real proxy and disposable Vault. The
// authority is the actual local session/grant store, not a hosted identity
// provider. This does not prove deployed runner isolation or actionref wiring.
func testRealVaultActorCancellation(t *testing.T, hc *hashicorp.Client, secret string, secure bool) {
	for _, withdrawal := range []string{"identity", "permission"} {
		t.Run(withdrawal, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			st, err := store.Open(filepath.Join(t.TempDir(), "actors.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			v, err := st.CreateVault(ctx, "actor-isolation")
			if err != nil {
				t.Fatal(err)
			}
			_, err = st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: v.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"http-reference","kv_version":2}`, PollIntervalSeconds: 60})
			if err != nil {
				t.Fatal(err)
			}
			var withdrawn atomic.Bool
			var callsA, callsB atomic.Int32
			startedA, startedB := make(chan struct{}), make(chan struct{})
			canceledA, canceledB := make(chan struct{}), make(chan struct{})
			recheckedB, releaseB := make(chan struct{}), make(chan struct{})
			var observedB sync.Once
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+secret || r.Header.Get("Proxy-Authorization") != "" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case "/approved/a":
					if callsA.Add(1) == 1 {
						close(startedA)
					}
					<-r.Context().Done()
					close(canceledA)
					return
				case "/approved/b":
					if callsB.Add(1) == 1 {
						close(startedB)
					}
					select {
					case <-r.Context().Done():
						close(canceledB)
						return
					case <-releaseB:
						_, _ = io.WriteString(w, `{"result":"approved","hidden":"fixture-only"}`)
					}
				default:
					http.NotFound(w, r)
				}
			}))
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
			services := []broker.Service{}
			for _, actor := range []string{"a", "b"} {
				services = append(services, broker.Service{Name: "read-" + actor, Host: u.Hostname(), Port: &port, Path: "/approved/" + actor, Auth: broker.Auth{Type: "bearer", Token: "REFERENCE_KEY"}})
			}
			encoded, err := json.Marshal(services)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.SetBrokerConfig(ctx, v.ID, string(encoded)); err != nil {
				t.Fatal(err)
			}
			resolver := brokercore.NewStoreSessionResolver(st)
			provider := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, make([]byte, 32))
			provider.RequestSecrets = hashicorp.RequestResolver{Store: st, Fetcher: hc}
			proxyURL, roots, proxy := setupProxy(t, resolver, provider)
			if secure {
				pool := x509.NewCertPool()
				pool.AddCert(upstream.Certificate())
				proxy.upstream.TLSClientConfig.RootCAs = pool
			}
			type actor struct {
				id, token string
				handler   http.Handler
			}
			actors := map[string]actor{}
			for _, name := range []string{"a", "b"} {
				expiry := time.Now().Add(time.Minute)
				agent, session, err := st.CreateAgentWithGrantsAndToken(ctx, "actor-"+name, "fixture", "no-access", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "proxy"}}, &expiry)
				if err != nil {
					t.Fatal(err)
				}
				client := newTrustingClient(proxyURL, url.UserPassword(session.ID, v.Name), roots)
				t.Cleanup(client.CloseIdleConnections)
				h, err := actionref.New(actionref.Config{
					Client: client, Upstream: upstream.URL + "/approved/" + name, Fields: []string{"result"},
					Poll: 10 * time.Millisecond, LookupTimeout: time.Second, MaxDuration: 5 * time.Second,
					Verify: func(check context.Context, token string) (actionref.Identity, error) {
						current, err := st.GetSession(check, token)
						if err != nil || current == nil || current.AgentID != agent.ID || current.IsExpired(time.Now()) {
							return actionref.Identity{}, fmt.Errorf("invalid fixture identity")
						}
						return actionref.Identity{Actor: agent.ID, Run: "run-" + name, Expires: expiry}, nil
					},
					Allow: func(check context.Context, id actionref.Identity) (bool, error) {
						role, err := st.GetVaultRole(check, id.Actor, v.ID)
						if name == "b" && withdrawn.Load() && err == nil && role == "proxy" {
							observedB.Do(func() { close(recheckedB) })
						}
						return role == "proxy", err
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				actors[name] = actor{id: agent.ID, token: session.ID, handler: h}
			}
			run := func(a actor) <-chan *httptest.ResponseRecorder {
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					r := httptest.NewRequest(http.MethodPost, "/actions/read", nil).WithContext(ctx)
					r.Header.Set("Authorization", "Bearer "+a.token)
					w := httptest.NewRecorder()
					a.handler.ServeHTTP(w, r)
					done <- w
				}()
				return done
			}
			wait := func(ch <-chan struct{}, label string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out: %s", label)
				}
			}
			response := func(done <-chan *httptest.ResponseRecorder, want int) *httptest.ResponseRecorder {
				t.Helper()
				select {
				case w := <-done:
					if w.Code != want {
						t.Fatalf("action status=%d want=%d", w.Code, want)
					}
					return w
				case <-time.After(2 * time.Second):
					t.Fatal("action response timed out")
					return nil
				}
			}
			doneA, doneB := run(actors["a"]), run(actors["b"])
			wait(startedA, "A upstream started")
			wait(startedB, "B upstream started")
			if withdrawal == "identity" {
				err = st.RevokeAgent(ctx, actors["a"].id)
			} else {
				err = st.RevokeVaultAccess(ctx, actors["a"].id, v.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			withdrawn.Store(true)
			wait(canceledA, "A upstream canceled")
			response(doneA, http.StatusForbidden)
			wait(recheckedB, "B grant rechecked after withdrawal")
			select {
			case <-canceledB:
				t.Fatal("A withdrawal canceled B")
			case <-doneB:
				t.Fatal("B completed before release")
			default:
			}
			close(releaseB)
			checkB := func(done <-chan *httptest.ResponseRecorder) {
				t.Helper()
				if response(done, http.StatusOK).Body.String() != "{\"result\":\"approved\"}\n" {
					t.Fatal("B result not filtered")
				}
			}
			checkB(doneB)
			checkB(run(actors["b"]))
			want := http.StatusForbidden
			if withdrawal == "identity" {
				want = http.StatusUnauthorized
			}
			response(run(actors["a"]), want)
			if callsA.Load() != 1 || callsB.Load() != 2 {
				t.Fatalf("upstream calls A=%d B=%d", callsA.Load(), callsB.Load())
			}
		})
	}
}

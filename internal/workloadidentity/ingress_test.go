package workloadidentity

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/jackc/pgx/v5/pgproto3"
)

type ingressCredentials struct{}

func (ingressCredentials) Inject(context.Context, string, string, int, string) (*brokercore.InjectResult, error) {
	return &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer destination-fixture"}, MatchedName: "fixture"}, nil
}

type ingressLeases struct{ minted atomic.Int64 }

func (l *ingressLeases) Mint(context.Context, string, *pgproxy.DatabaseService) (*pgproxy.Lease, error) {
	n := l.minted.Add(1)
	return &pgproxy.Lease{ID: fmt.Sprintf("fixture-%d", n), Username: "destination-user", Password: "destination-fixture", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (*ingressLeases) Renew(context.Context, string, time.Duration) (time.Time, error) {
	return time.Now().Add(time.Minute), nil
}
func (*ingressLeases) Revoke(context.Context, string) error { return nil }

// Both real ingress implementations consume the same real resolver here.
// Kubernetes, Vault issuance and the PostgreSQL destination are synthetic;
// passing this test establishes integration wiring, not deployed acceptance.
type ingressDenial struct {
	name   string
	change func()
	raw    func() string
}

func TestProjectedProofAcrossHTTPAndPostgres(t *testing.T) {
	f := setup(t)
	scope, err := server.NewAgentAuthAdapter(f.r).Authenticate(context.Background(), token(f.c), "")
	if err != nil || scope.WorkloadID != "pod-uid" {
		t.Fatal("PostgreSQL adapter lost verified workload identity")
	}
	exerciseIngress(t, f.r, token(f.c), []ingressDenial{{"standing-token", func() {}, func() string { return "standing-agent-token" }},
		{"wrong-audience", func() { f.c.Audience = []string{"other"} }, func() string { return token(f.c) }},
		{"revoked-grant", func() { f.c.Audience = []string{"credential-proxy"}; f.s.role = "" }, func() string { return token(f.c) }},
		{"deleted-pod", func() { f.s.role = "proxy"; f.podStatus = 404 }, func() string { return token(f.c) }},
		{"verifier-outage", func() { f.podStatus = 200; f.reviewStatus = 503 }, func() string { return token(f.c) }},
	})
}

func exerciseIngress(t *testing.T, resolver *Resolver, proof string, denials []ingressDenial) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_TOKEN", "")
	var httpCalls, pgCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "Bearer destination-fixture" {
			t.Error("proof leaked or destination credential missing")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxy := mitm.New("127.0.0.1:0", mitm.Options{Sessions: resolver, Credentials: ingressCredentials{}, Logger: slog.New(slog.DiscardHandler)})
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve(httpLn)
	t.Cleanup(func() { proxy.Shutdown(context.Background()) })
	proxyURL := &url.URL{Scheme: "http", Host: httpLn.Addr().String()}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	httpAttempt := func(raw string) int {
		req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+raw)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	pgUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pgUpstream.Close()
	go func() {
		for {
			c, err := pgUpstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				be := pgproto3.NewBackend(c, c)
				m, err := be.ReceiveStartupMessage()
				if err != nil {
					return
				}
				startup, ok := m.(*pgproto3.StartupMessage)
				if !ok || startup.Parameters["user"] != "destination-user" {
					t.Error("invalid destination startup")
					return
				}
				pgCalls.Add(1)
				be.Send(&pgproto3.AuthenticationOk{})
				be.Send(&pgproto3.BackendKeyData{ProcessID: 12, SecretKey: []byte{0, 0, 0, 34}})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if be.Flush() != nil {
					return
				}
				for {
					m, err := be.Receive()
					if err != nil {
						return
					}
					switch m.(type) {
					case *pgproto3.Query:
						be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
						be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
						if be.Flush() != nil {
							return
						}
					case *pgproto3.Terminate:
						return
					}
				}
			}()
		}
	}()
	leases := &ingressLeases{}
	pgBroker := pgproxy.New("127.0.0.1:0", pgproxy.Options{Auth: server.NewAgentAuthAdapter(resolver), Databases: server.NewStaticDatabaseResolver(map[string][]pgproxy.DatabaseService{"allowed": {{Name: "fixture", Addr: pgUpstream.Addr().String(), Database: "fixture", Mount: "database", Role: "readonly", SSLMode: "disable"}}}), Leases: leases})
	pgLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go pgBroker.Serve(pgLn)
	t.Cleanup(func() { pgBroker.Shutdown(context.Background()) })
	pgAttempt := func(raw string) error { return postgresAttempt(pgLn.Addr().String(), raw) }

	if status := httpAttempt(proof); status != 204 {
		t.Fatalf("HTTP positive control status %d", status)
	}
	if err := pgAttempt(proof); err != nil {
		t.Fatalf("PostgreSQL positive control: %v", err)
	}
	if httpCalls.Load() != 1 || pgCalls.Load() != 1 || leases.minted.Load() != 1 {
		t.Fatal("positive control did not reach both destinations")
	}
	for _, test := range denials {
		t.Run(test.name, func(t *testing.T) {
			test.change()
			if status := httpAttempt(test.raw()); status < 400 {
				t.Fatalf("HTTP denial returned %d", status)
			}
			if err := pgAttempt(test.raw()); err == nil {
				t.Fatal("PostgreSQL denied proof admitted")
			}
			if httpCalls.Load() != 1 || pgCalls.Load() != 1 || leases.minted.Load() != 1 {
				t.Fatal("denied identity reached destination or minted credentials")
			}
		})
	}
}

func postgresAttempt(addr, proof string) error {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fe := pgproto3.NewFrontend(c, c)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "fixture"}})
	if err := fe.Flush(); err != nil {
		return err
	}
	ready := false
	for {
		m, err := fe.Receive()
		if err != nil {
			return err
		}
		switch m.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: proof})
			if err := fe.Flush(); err != nil {
				return err
			}
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("broker denied PostgreSQL request")
		case *pgproto3.ReadyForQuery:
			if ready {
				fe.Send(&pgproto3.Terminate{})
				return fe.Flush()
			}
			ready = true
			fe.Send(&pgproto3.Query{String: "SELECT 1"})
			if err := fe.Flush(); err != nil {
				return err
			}
		}
	}
}

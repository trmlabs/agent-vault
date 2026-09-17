//go:build realcombined

package mitm

import (
	"bufio"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

type combinedPublicConfig struct {
	BrokerIP    string
	ServiceIP   string
	Destination string
	RootsPEM    string
}

// Direct fixture ports provide positive controls before NetworkPolicy is applied.
// They forward to real services, all colocated in the trusted broker test pod.
func combinedDirectPort(t *testing.T, port, target string) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	go func() {
		defer close(accepted)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer func() { _ = conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-accepted
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
}

func combinedInPodGate(t *testing.T, ctx context.Context, destination string, proxyCA, transportDER []byte) {
	t.Helper()
	podIP, serviceIP := os.Getenv("AV_COMBINED_POD_IP"), os.Getenv("AV_COMBINED_SERVICE_IP")
	if net.ParseIP(podIP) == nil || net.ParseIP(serviceIP) == nil {
		t.Fatal("in-pod fixture requires broker pod and service IPs")
	}
	u, err := url.Parse(destination)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	combinedDirectPort(t, "14444", u.Host)
	combinedDirectPort(t, "15444", os.Getenv("AV_TEST_PG_UPSTREAM"))
	combinedDirectPort(t, "18444", vault.Host)
	config := combinedPublicConfig{BrokerIP: podIP, ServiceIP: serviceIP, Destination: destination, RootsPEM: string(proxyCA) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transportDER}))}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	// Build privately, then publish without overwriting an existing file or symlink.
	// The hard link exposes only the complete configuration to the fixture runner.
	publicConfig, err := os.CreateTemp("/tmp", "combined-public-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = publicConfig.Close()
		_ = os.Remove(publicConfig.Name())
	}()
	if _, err := publicConfig.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := publicConfig.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(publicConfig.Name(), "/tmp/combined-public.json"); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat("/tmp/combined-agent-complete"); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("in-pod client proof did not complete")
		case <-ticker.C:
		}
	}
	t.Log("actual caller pod completed permitted HTTP/PG work; direct HTTP/PG/Vault routes passed before policy and failed on pod/service IPs after policy")
}

// This helper runs only inside the separately created caller pod. Its proof is
// read from that pod's projected volume, not provided by the broker process.
func TestRealCombinedAgentClient(t *testing.T) {
	action := os.Getenv("AV_COMBINED_CLIENT_ACTION")
	if action == "" {
		t.Skip("in-pod caller helper")
	}
	data, err := os.ReadFile("/tmp/combined-public.json")
	if err != nil {
		t.Fatal("missing public fixture configuration")
	}
	var cfg combinedPublicConfig
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid fixture configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.RootsPEM)) {
		t.Fatal("fixture trust missing")
	}
	for _, ip := range []string{cfg.BrokerIP, cfg.ServiceIP} {
		if net.ParseIP(ip) == nil {
			t.Fatal("fixture requires literal destination IPs")
		}
		for _, port := range []string{"14444", "15444", "18444"} {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 350*time.Millisecond)
			if action == "control" && err != nil {
				t.Fatalf("direct-route positive control failed: port=%s", port)
			}
			if action == "isolated" && err == nil {
				_ = conn.Close()
				t.Fatalf("direct route remained reachable: port=%s", port)
			}
			if conn != nil {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				switch port {
				case "14444":
					secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
					if err := secured.Handshake(); err != nil {
						_ = conn.Close()
						t.Fatal("direct TLS destination unavailable")
					}
					_, err = io.WriteString(secured, "GET /approved HTTP/1.0\r\nHost: fixture\r\n\r\n")
					response, readErr := http.ReadResponse(bufio.NewReader(secured), nil)
					if err != nil || readErr != nil || response.StatusCode != http.StatusUnauthorized {
						_ = conn.Close()
						t.Fatal("direct HTTP control did not reach destination")
					}
					_ = response.Body.Close()
				case "18444":
					_, err = io.WriteString(conn, "GET /v1/sys/health HTTP/1.0\r\nHost: fixture\r\n\r\n")
					response, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil || readErr != nil || response.StatusCode != http.StatusOK {
						_ = conn.Close()
						t.Fatal("direct Vault control did not reach healthy service")
					}
					_ = response.Body.Close()
				case "15444":
					packet, encodeErr := (&pgproto3.SSLRequest{}).Encode(nil)
					if encodeErr != nil {
						_ = conn.Close()
						t.Fatal(encodeErr)
					}
					_, err = conn.Write(packet)
					var answer [1]byte
					_, readErr := io.ReadFull(conn, answer[:])
					if err != nil || readErr != nil || (answer[0] != 'N' && answer[0] != 'S') {
						_ = conn.Close()
						t.Fatal("direct PostgreSQL control did not reach database")
					}
				}
				_ = conn.Close()
			}
		}
	}
	if action == "control" {
		t.Log("direct HTTP/PostgreSQL/Vault controls reachable by pod IP and service IP")
		return
	}
	if action != "isolated" {
		t.Fatal("unknown fixture action")
	}
	proofBytes, err := os.ReadFile("/proof/allowed")
	if err != nil {
		t.Fatal("projected pod proof unavailable")
	}
	proof := strings.TrimSpace(string(proofBytes))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The expected server name is fixed independently of the route IP.
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "https", Host: net.JoinHostPort(cfg.BrokerIP, "14443")}), TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}, ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer " + proof}}}
	defer transport.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Destination+"/approved", nil)
	req.Header.Set("Authorization", "Bearer __vault_API_KEY__")
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal("in-pod encrypted HTTP workflow failed")
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "approved-output" {
		t.Fatal("in-pod HTTP output incorrect")
	}
	pgAddr := net.JoinHostPort(cfg.BrokerIP, "15443")
	pgcfg, err := pgx.ParseConfig("postgres://" + pgAddr + "/database?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pgcfg.User, pgcfg.Password = "workload", proof
	pgcfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}}).DialContext(ctx, "tcp", pgAddr)
	}
	pg, err := pgx.ConnectConfig(ctx, pgcfg)
	if err != nil {
		t.Fatal("in-pod encrypted PostgreSQL workflow failed")
	}
	defer func() { _ = pg.Close(context.Background()) }()
	var count int
	if err := pg.QueryRow(ctx, "SELECT count(*) FROM customers").Scan(&count); err != nil || count == 0 {
		t.Fatal("in-pod PostgreSQL result incorrect")
	}
	t.Log("actual pod proof admitted HTTP/PostgreSQL via verified TLS; direct services denied by pod/service IP; no destination credential received")
}

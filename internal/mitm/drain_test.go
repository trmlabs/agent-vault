package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// drainFixture is a proxy in front of an upstream whose /slow handler waits
// for release, so a test can hold a request in flight across Shutdown.
type drainFixture struct {
	proxyURL *url.URL
	roots    *x509.CertPool
	p        *Proxy
	target   string
	started  chan struct{}
	release  chan struct{}
}

func newDrainFixture(t *testing.T, drain bool) *drainFixture {
	t.Helper()
	f := &drainFixture{started: make(chan struct{}, 4), release: make(chan struct{})}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			f.started <- struct{}{}
			select {
			case <-f.release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "done")
	}))
	t.Cleanup(upstream.Close)
	f.target = strings.TrimPrefix(upstream.URL, "https://")
	host, _, _ := net.SplitHostPort(f.target)
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer injected"}}},
	}}
	f.proxyURL, f.roots, f.p = setupProxy(t, sr, cp, func(o *Options) { o.DrainTunnels = drain })
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	f.p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	return f
}

// tunnel opens a CONNECT tunnel and the worker's TLS session inside it.
func (f *drainFixture) tunnel(t *testing.T) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	raw := openMITMTunnel(t, f.proxyURL, f.roots, f.target, "av_sess_ok")
	host, _, _ := net.SplitHostPort(f.target)
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots, ServerName: host})
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tunnel TLS handshake: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func send(t *testing.T, conn *tls.Conn, target, path string) {
	t.Helper()
	if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

// receive reads one response: its status, whether it closes the
// connection, and its body.
func receive(t *testing.T, reader *bufio.Reader) (int, bool, string) {
	t.Helper()
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Close, string(body)
}

// closedByProxy is true for an error from the proxy ending the connection,
// not from the test's own read deadline.
func closedByProxy(err error) bool {
	var timeout net.Error
	return err != nil && (!errors.As(err, &timeout) || !timeout.Timeout())
}

func shutdownAsync(p *Proxy, timeout time.Duration) <-chan error {
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		done <- p.Shutdown(ctx)
	}()
	return done
}

func TestShutdownDrainFinishesInFlightTunnelRequest(t *testing.T) {
	f := newDrainFixture(t, true)
	conn, reader := f.tunnel(t)
	send(t, conn, f.target, "/slow")
	<-f.started

	done := shutdownAsync(f.p, 5*time.Second)
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned with a request in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if c, err := net.DialTimeout("tcp", f.proxyURL.Host, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a draining proxy still accepted a new connection")
	}

	close(f.release)
	status, closing, body := receive(t, reader)
	if status != http.StatusOK || body != "done" {
		t.Fatalf("in-flight request = %d %q, want 200 done", status, body)
	}
	if !closing {
		t.Fatal("a drained response must carry Connection: close")
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("tunnel after drain: %v, want EOF", err)
	}
}

func TestShutdownDrainClosesIdleTunnelAtOnce(t *testing.T) {
	f := newDrainFixture(t, true)
	conn, reader := f.tunnel(t)
	send(t, conn, f.target, "/fast")
	if status, closing, body := receive(t, reader); status != http.StatusOK || body != "done" || closing {
		t.Fatalf("keep-alive request = %d %q close=%v", status, body, closing)
	}

	started := time.Now()
	if err := <-shutdownAsync(f.p, 5*time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("idle tunnel held Shutdown for %v", elapsed)
	}
	if _, err := reader.ReadByte(); !closedByProxy(err) {
		t.Fatalf("idle tunnel after Shutdown: %v, want closed by the proxy", err)
	}
}

func TestShutdownDrainForceClosesAtDeadline(t *testing.T) {
	f := newDrainFixture(t, true)
	conn, reader := f.tunnel(t)
	send(t, conn, f.target, "/slow")
	<-f.started
	t.Cleanup(func() { close(f.release) })

	started := time.Now()
	<-shutdownAsync(f.p, 300*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Shutdown overran its deadline: %v", elapsed)
	}
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err == nil {
		_ = resp.Body.Close()
	}
	if !closedByProxy(err) {
		t.Fatalf("request past the deadline: %v, want the connection closed by the proxy", err)
	}
}

func TestShutdownDrainRefusesNewTunnel(t *testing.T) {
	f := newDrainFixture(t, true)
	<-shutdownAsync(f.p, time.Second)

	req := httptest.NewRequest(http.MethodConnect, "http://"+f.target, nil)
	req.Host = f.target
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("av_sess_ok:")))
	rec := httptest.NewRecorder()
	f.p.dispatch(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT while draining = %d, want 503", rec.Code)
	}
}

// Without DrainTunnels, Shutdown keeps its old behavior: it does not wait for
// tunnels, and an open tunnel keeps working until the process ends.
func TestShutdownWithoutDrainLeavesTunnels(t *testing.T) {
	f := newDrainFixture(t, false)
	conn, reader := f.tunnel(t)
	send(t, conn, f.target, "/slow")
	<-f.started

	select {
	case <-shutdownAsync(f.p, 5*time.Second):
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown without drain waited on an open tunnel")
	}
	close(f.release)
	status, closing, body := receive(t, reader)
	if status != http.StatusOK || body != "done" || closing {
		t.Fatalf("untracked tunnel = %d %q close=%v, want an unchanged keep-alive 200", status, body, closing)
	}
}

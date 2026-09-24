//go:build linux || darwin

package taskrelay

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStartupDoesNotAdmitBeforeBrowserPolicyValidation(t *testing.T) {
	f := newRelayFixture(t)
	backend := newBindingBackend(t, f, "first")
	f.c.PostgresBindings = []PostgresConfig{{Listen: freeAddress(t), Upstream: f.upstream(t, backend.listener.Addr().String()), Database: "first", User: "workload", Placeholder: "public-placeholder"}}
	fifo := filepath.Join(t.TempDir(), "pending-ca")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(fifo, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	up := f.upstream(t, "127.0.0.1:25444")
	up.CAFile = fifo
	f.c.Browser = &BrowserConfig{Listen: freeAddress(t), Upstream: up}
	done := make(chan error, 1)
	go func() { done <- Run(t.Context(), f.c) }()
	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", f.c.PostgresBindings[0].Listen, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("earlier listener never bound")
	}
	defer conn.Close()
	config, err := clientTLS(f.c.TLSCertFile, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if err := tls.Client(conn, config).Handshake(); err == nil {
		t.Error("earlier listener admitted TLS before final policy validation")
	}
	_, _ = writer.Write([]byte("invalid CA"))
	_ = writer.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("invalid browser trust accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not fail")
	}
	if backend.arrivals.Load() != 0 {
		t.Fatal("upstream received work during incomplete startup")
	}
}

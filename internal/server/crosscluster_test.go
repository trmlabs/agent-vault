package server

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// loopbackPair is a connection accepted on loopback, as from the TLS front.
func loopbackPair(t *testing.T, send string) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			_, _ = io.WriteString(c, send)
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

const proxyLine = "PROXY TCP4 10.200.0.7 10.0.0.1 51000 16443\r\n"

func TestCrossClusterRoutesByFirstBytes(t *testing.T) {
	for name, c := range map[string]struct {
		send     string
		postgres bool
		ok       bool
	}{
		"PostgreSQL attestation preamble": {proxyLine + "GHATTS1 abc\nrest", true, true},
		"HTTP CONNECT":                    {proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", false, true},
		"plain PostgreSQL startup":        {proxyLine + "\x00\x00\x00\x08\x04\xd2\x16\x2f", false, false},
		"plain HTTP request":              {proxyLine + "GET / HTTP/1.1\r\n\r\n", false, false},
		"session preamble only":           {proxyLine + "GHSESS1 a.b.c\n", false, false},
		"no PROXY header":                 {"CONNECT h:443 HTTP/1.1\r\n\r\n", false, false},
	} {
		routed, postgres, err := routeCrossCluster(loopbackPair(t, c.send))
		if (err == nil) != c.ok || (c.ok && postgres != c.postgres) {
			t.Errorf("%s: postgres %v err %v", name, postgres, err)
			continue
		}
		if !c.ok {
			continue
		}
		// The server that gets it reads every byte, PROXY header first, and
		// admits only proxy-attested identities.
		b, _ := io.ReadAll(routed)
		if string(b) != c.send || !brokercore.KindAdmitted(brokercore.ConnKinds(routed), brokercore.KindProxyAttested) ||
			brokercore.KindAdmitted(brokercore.ConnKinds(routed), brokercore.KindPodToken) {
			t.Errorf("%s: replayed %q", name, b)
		}
	}
}

func TestMergedListenerServesBothAndCloses(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newMergedListener(l)
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	if c, err := m.Accept(); err != nil {
		t.Fatalf("own connection: %v", err)
	} else {
		c.Close()
	}
	a, b := net.Pipe()
	defer b.Close()
	go m.inject(a)
	if c, err := m.Accept(); err != nil || c != a {
		t.Fatalf("injected connection: %v", err)
	}
	_ = m.Close()
	if _, err := m.Accept(); err == nil {
		t.Fatal("accepted after close")
	}
	x, y := net.Pipe()
	defer y.Close()
	m.inject(x) // closed, not blocked
	if _, err := x.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("injection after close left the connection open: %v", err)
	}
}

func TestCrossClusterListenerMustBeLoopback(t *testing.T) {
	s := &Server{}
	if s.EnableCrossCluster("0.0.0.0:14325") == nil || s.EnableCrossCluster("10.0.0.1:14325") == nil {
		t.Fatal("a non-loopback cross-cluster listener was accepted")
	}
	if err := s.EnableCrossCluster("127.0.0.1:14325"); err != nil || s.crossClusterAddr != "127.0.0.1:14325" {
		t.Fatalf("loopback refused: %v", err)
	}
}

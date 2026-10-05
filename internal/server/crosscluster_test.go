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
		"no PROXY header, PostgreSQL":     {"GHATTS1 abc\n", false, false},
		"a second PROXY line":             {proxyLine + proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", false, false},
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
	for _, addr := range []string{"0.0.0.0:14325", "10.0.0.1:14325", "[::]:14325", ":14325", "localhost:14325", "127.0.0.2:14325", "[::1]:14325"} {
		if s.EnableCrossCluster(addr) == nil {
			t.Errorf("cross-cluster listener on %s accepted", addr)
		}
	}
	if err := s.EnableCrossCluster("127.0.0.1:14325"); err != nil || s.crossClusterAddr != "127.0.0.1:14325" {
		t.Fatalf("loopback refused: %v", err)
	}
}

// remoteConn reports another remote address, as if the TCP peer were not the
// TLS front in the same Pod.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// The PROXY header is trusted only from a loopback TCP peer: a valid-looking
// header from anywhere else is refused.
func TestCrossClusterTrustsPROXYOnlyFromLoopback(t *testing.T) {
	c := loopbackPair(t, proxyLine+"CONNECT h:443 HTTP/1.1\r\n\r\n")
	peer := remoteConn{Conn: c, remote: &net.TCPAddr{IP: net.ParseIP("10.200.0.7"), Port: 51000}}
	if _, _, err := routeCrossCluster(peer); err == nil {
		t.Fatal("a PROXY header from a non-loopback peer was trusted")
	}
}

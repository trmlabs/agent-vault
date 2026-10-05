package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// The cross-cluster listener serves agents in another cluster, through the
// shared proxy there and a private link. It admits only proxy-attested
// identities, and carries both protocols on one port: after the TLS front's
// PROXY header, a shared proxy's PostgreSQL stream opens with its
// attestation preamble and its HTTP stream with CONNECT. Every other start is
// closed. Routed connections join the existing HTTP proxy and PostgreSQL
// broker listeners, tagged so those admit them only as proxy-attested.

// EnableCrossCluster opens the cross-cluster listener on 127.0.0.1, behind a
// TLS front in the same Pod that sends a PROXY header. It needs the
// credential proxy.
func (s *Server) EnableCrossCluster(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return errors.New("the cross-cluster listener binds 127.0.0.1 only, behind its TLS front")
	}
	s.crossClusterAddr = addr
	return nil
}

var crossClusterKinds = []string{brokercore.KindProxyAttested}

const crossClusterRouteTimeout = 5 * time.Second

// mergedListener yields the connections of an existing listener plus those a
// dispatcher injects. Closing it closes the existing listener and stops the
// injections.
type mergedListener struct {
	net.Listener
	injected chan net.Conn
	accepted chan acceptResult
	done     chan struct{}
	once     sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newMergedListener(l net.Listener) *mergedListener {
	m := &mergedListener{Listener: l, injected: make(chan net.Conn), accepted: make(chan acceptResult), done: make(chan struct{})}
	go func() {
		for {
			c, err := l.Accept()
			select {
			case m.accepted <- acceptResult{c, err}:
			case <-m.done:
				if c != nil {
					_ = c.Close()
				}
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return m
}

func (m *mergedListener) Accept() (net.Conn, error) {
	select {
	case r := <-m.accepted:
		return r.conn, r.err
	case c := <-m.injected:
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *mergedListener) Close() error {
	m.once.Do(func() { close(m.done) })
	return m.Listener.Close()
}

// inject hands a routed connection to the listener's server, or closes it
// when the listener has closed.
func (m *mergedListener) inject(c net.Conn) {
	select {
	case m.injected <- c:
	case <-m.done:
		_ = c.Close()
	}
}

var errUnrouted = errors.New("cross-cluster connection is neither attested HTTP nor PostgreSQL")

// routeCrossCluster reads the TLS front's PROXY header and the first eight
// bytes after it, without consuming them for the server that gets the
// connection, and says where it goes.
func routeCrossCluster(c net.Conn) (*brokercore.KindedConn, bool, error) {
	_ = c.SetReadDeadline(time.Now().Add(crossClusterRouteTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var seen bytes.Buffer
	if _, err := brokercore.ReadProxyV1(io.TeeReader(c, &seen), c.RemoteAddr()); err != nil {
		return nil, false, err
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, false, err
	}
	seen.Write(head)
	routed := &brokercore.KindedConn{Conn: c, Kinds: crossClusterKinds, Prefix: bytes.NewReader(seen.Bytes())}
	switch string(head) {
	case "GHATTS1 ":
		return routed, true, nil
	case "CONNECT ":
		return routed, false, nil
	}
	return nil, false, errUnrouted
}

// serveCrossCluster routes each connection of l to the PostgreSQL broker's
// or the HTTP proxy's listener; either may be nil, and its traffic is then
// closed.
func serveCrossCluster(l net.Listener, httpLn, pgLn *mergedListener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			routed, postgres, err := routeCrossCluster(c)
			switch {
			case err != nil:
				_ = c.Close()
			case postgres && pgLn != nil:
				pgLn.inject(routed)
			case !postgres && httpLn != nil:
				httpLn.inject(routed)
			default:
				_ = c.Close()
			}
		}()
	}
}

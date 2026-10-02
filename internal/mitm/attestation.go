package mitm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// PeerReader returns the worker's address for an accepted connection, for
// example from a PROXY header written by a loopback TLS terminator. It must
// read no further than the header itself.
type PeerReader func(net.Conn) (netip.Addr, error)

var errNoPeer = errors.New("connection peer unavailable")

// peerListener resolves each connection's peer lazily, on the connection's
// own goroutine at its first read, so a stalled client cannot block Accept.
type peerListener struct {
	net.Listener
	reader PeerReader
}

func (l peerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &peerConn{Conn: c, reader: l.reader}, nil
}

type peerConn struct {
	net.Conn
	reader PeerReader
	once   sync.Once
	peer   netip.Addr
	err    error
}

func (c *peerConn) resolve() {
	c.once.Do(func() {
		remote, err := netip.ParseAddrPort(c.Conn.RemoteAddr().String())
		if err != nil {
			c.err = errNoPeer
			return
		}
		if c.reader == nil {
			c.peer = remote.Addr().Unmap()
			return
		}
		// A PROXY header is trusted only from a loopback terminator.
		if !remote.Addr().Unmap().IsLoopback() {
			c.err = errNoPeer
			return
		}
		_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		c.peer, c.err = c.reader(c.Conn)
		_ = c.Conn.SetReadDeadline(time.Time{})
		if c.err != nil {
			c.err = errNoPeer
		}
	})
}

func (c *peerConn) Read(b []byte) (int, error) {
	c.resolve()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

// Peer is valid once the connection has been read, which the HTTP server does
// before any handler runs.
func (c *peerConn) Peer() (netip.Addr, error) {
	c.resolve()
	return c.peer, c.err
}

type peerContextKey struct{}

func withPeerConn(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*peerConn); ok {
		return context.WithValue(ctx, peerContextKey{}, pc)
	}
	return ctx
}

func peerFromContext(ctx context.Context) (netip.Addr, error) {
	pc, ok := ctx.Value(peerContextKey{}).(*peerConn)
	if !ok {
		return netip.Addr{}, errNoPeer
	}
	return pc.Peer()
}

// resolveScope admits a worker. With an Attestor it uses the projected token
// and the connection's real peer; the token-review SessionResolver is used
// only when no Attestor is configured. A scope past its NotAfter is refused.
func (p *Proxy) resolveScope(ctx context.Context, token, hint string, peer netip.Addr, peerErr error) (*brokercore.ProxyScope, error) {
	if p.attestor == nil {
		return p.sessions.ResolveForProxy(ctx, token, hint)
	}
	if peerErr != nil || !peer.IsValid() {
		return nil, brokercore.ErrInvalidSession
	}
	scope, err := p.attestor.Attest(ctx, token, peer)
	if err != nil || scope == nil {
		return nil, brokercore.ErrInvalidSession
	}
	if !scope.NotAfter.IsZero() && !time.Now().Before(scope.NotAfter) {
		return nil, brokercore.ErrInvalidSession
	}
	return scope, nil
}

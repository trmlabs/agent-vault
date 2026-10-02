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

	mu       sync.Mutex
	deadline time.Time // the read deadline the HTTP server last set
}

// SetReadDeadline and SetDeadline record the server's read deadline, so
// reading the PROXY header can put it back instead of clearing it.
func (c *peerConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *peerConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
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
		// The header gets at most 5 seconds, and never more than the server's
		// own header timeout; the server's deadline is restored afterwards, so
		// its header and read timeouts keep applying to the request.
		c.mu.Lock()
		restore := c.deadline
		c.mu.Unlock()
		header := time.Now().Add(5 * time.Second)
		if !restore.IsZero() && restore.Before(header) {
			header = restore
		}
		_ = c.Conn.SetReadDeadline(header)
		c.peer, c.err = c.reader(c.Conn)
		_ = c.Conn.SetReadDeadline(restore)
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
// only when no Attestor is configured. A recheck inside an open tunnel uses
// Reattest when the Attestor has it, because the tunnel outlives its token.
// A scope past its NotAfter is refused.
func (p *Proxy) resolveScope(ctx context.Context, token, hint string, peer netip.Addr, peerErr error, recheck bool) (*brokercore.ProxyScope, error) {
	if p.attestor == nil {
		return p.sessions.ResolveForProxy(ctx, token, hint)
	}
	if peerErr != nil || !peer.IsValid() {
		return nil, brokercore.ErrInvalidSession
	}
	var scope *brokercore.ProxyScope
	var err error
	if again, ok := p.attestor.(brokercore.Reattestor); ok && recheck {
		scope, err = again.Reattest(ctx, token, peer)
	} else {
		scope, err = p.attestor.Attest(ctx, token, peer)
	}
	if err != nil || scope == nil {
		return nil, brokercore.ErrInvalidSession
	}
	if !scope.NotAfter.IsZero() && !time.Now().Before(scope.NotAfter) {
		return nil, brokercore.ErrInvalidSession
	}
	return scope, nil
}

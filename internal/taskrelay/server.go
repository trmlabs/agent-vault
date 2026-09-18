package taskrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const handshakeTimeout = 10 * time.Second
const maxConnections = 32

type relay struct {
	config        FixedConfig
	pair          *pairVerifier
	audit         *relayAudit
	ctx           context.Context
	cancel        context.CancelFunc
	slots         chan struct{}
	wg            sync.WaitGroup
	cancelMu      sync.Mutex
	cancellations map[string]*cancelTarget
	workMu        sync.Mutex
	stopping      bool
}

// Run serves native TLS only. Failure of any listener, pairing, deadline or
// durable audit terminates the whole task. Supervisory detection is bounded by
// the one-second polling interval plus the three-second Kubernetes timeout.
func Run(parent context.Context, c FixedConfig) (result error) {
	if e := c.Validate(time.Now()); e != nil {
		return e
	}
	pair, e := newPairVerifier(c)
	if e != nil {
		return e
	}
	defer pair.client.CloseIdleConnections()
	if e = pair.check(parent, ""); e != nil {
		return e
	}
	audit, e := newAudit(c)
	if e != nil {
		return e
	}
	defer func() { _ = audit.file.Close() }()
	ctx, cancel := context.WithDeadline(parent, c.Deadline)
	defer cancel()
	r := &relay{config: c, pair: pair, audit: audit, ctx: ctx, cancel: cancel, slots: make(chan struct{}, maxConnections)}
	cert, e := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if e != nil {
		return errConfig
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	var listeners []net.Listener
	defer func() {
		r.workMu.Lock()
		r.stopping = true
		r.workMu.Unlock()
		cancel()
		for _, l := range listeners {
			_ = l.Close()
		}
		r.wg.Wait()
		if audit.record("relay", "terminal") != nil {
			result = errDenied
		}
	}()
	bind := func(address string) (net.Listener, error) {
		plain, e := net.Listen("tcp", address)
		if e != nil {
			return nil, e
		}
		l := tls.NewListener(&boundedListener{Listener: plain, slots: make(chan struct{}, maxConnections)}, tlsConfig)
		if e == nil {
			listeners = append(listeners, l)
		}
		return l, e
	}
	failures := make(chan error, 3)
	serveHTTP := func(l net.Listener, h http.Handler) {
		tracked := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !r.beginWork() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			defer r.wg.Done()
			h.ServeHTTP(w, req)
		})
		s := &http.Server{Handler: tracked, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: handshakeTimeout, ReadTimeout: handshakeTimeout, WriteTimeout: handshakeTimeout, IdleTimeout: handshakeTimeout, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			stop := context.AfterFunc(ctx, func() { _ = s.Close() })
			defer stop()
			if e := s.Serve(l); e != nil && ctx.Err() == nil {
				failures <- errDenied
			}
		}()
	}
	if c.Connect != nil {
		l, e := bind(c.Connect.Listen)
		if e != nil {
			return errConfig
		}
		serveHTTP(l, http.HandlerFunc(r.connect))
	}
	if c.Postgres != nil {
		l, e := bind(c.Postgres.Listen)
		if e != nil {
			return errConfig
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			stop := context.AfterFunc(ctx, func() { _ = l.Close() })
			defer stop()
			for {
				conn, e := l.Accept()
				if e != nil {
					if ctx.Err() == nil {
						failures <- errDenied
					}
					return
				}
				if !r.acquire() {
					_ = conn.Close()
					continue
				}
				if !r.beginWork() {
					r.release()
					_ = conn.Close()
					return
				}
				go func() {
					defer r.wg.Done()
					defer r.release()
					defer func() { _ = conn.Close() }()
					stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
					defer stop()
					r.postgres(conn)
				}()
			}
		}()
	}
	if c.Browser != nil {
		bc := c.Browser
		ca, e := readBoundedFile(bc.Upstream.CAFile, 1<<20)
		if e != nil {
			return errConfig
		}
		// Browser HTTPS endpoints use address host as the verified TLS name.
		host, _, _ := net.SplitHostPort(bc.Upstream.Address)
		if host != bc.Upstream.ServerName {
			return errConfig
		}
		b, e := NewBrowserRelay(BrowserOptions{Endpoint: "https://" + bc.Upstream.Address, CA: ca, Task: c.TaskID, Deadline: c.Deadline,
			Proof:     func(context.Context) (string, error) { p, _, e := readProjectedProof(bc.Upstream); return p, e },
			Authorize: pair.check, Audit: func(_ context.Context, op, outcome string) error { return r.record("browser", op+":"+outcome) }})
		if e != nil {
			return errConfig
		}
		defer func() {
			cancel()
			closeCtx, stop := context.WithTimeout(context.Background(), handshakeTimeout)
			defer stop()
			outcome := "cleanup-closed"
			if closeErr := b.Close(closeCtx); closeErr != nil {
				outcome = "cleanup-failed"
				if errors.Is(closeErr, errBrowserCleanupUnknown) {
					outcome = "cleanup-unknown"
				}
				result = errDenied
			}
			if r.record("browser", outcome) != nil {
				result = errDenied
			}
		}()
		l, e := bind(bc.Listen)
		if e != nil {
			return errConfig
		}
		serveHTTP(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !r.acquire() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			defer r.release()
			b.ServeHTTP(w, req)
		}))
	}
	ticker := time.NewTicker(pairInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if parent.Err() == nil && time.Now().Before(c.Deadline) {
				return errDenied
			}
			return nil
		case <-failures:
			return errDenied
		case <-ticker.C:
			if pair.check(ctx, "") != nil {
				return errDenied
			}
		}
	}
}

func (r *relay) beginWork() bool {
	r.workMu.Lock()
	defer r.workMu.Unlock()
	if r.stopping || r.ctx.Err() != nil {
		return false
	}
	r.wg.Add(1)
	return true
}

type boundedListener struct {
	net.Listener
	slots chan struct{}
}
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &countedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

func (r *relay) acquire() bool {
	select {
	case <-r.ctx.Done():
		return false
	default:
	}
	select {
	case r.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (r *relay) release() { <-r.slots }
func (r *relay) record(protocol, outcome string) error {
	if e := r.audit.record(protocol, outcome); e != nil {
		r.cancel()
		return e
	}
	return nil
}
func (r *relay) admit(ctx context.Context, peer, protocol string) error {
	if r.ctx.Err() != nil || r.pair.check(ctx, peer) != nil {
		return errDenied
	}
	return r.record(protocol, "admitted")
}
func dialUpstream(ctx context.Context, c UpstreamConfig) (net.Conn, error) {
	t, e := clientTLS(c.CAFile, c.ServerName)
	if e != nil {
		return nil, e
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: handshakeTimeout}, Config: t}
	return d.DialContext(ctx, "tcp", c.Address)
}

func copyTunnel(ctx context.Context, a net.Conn, ar io.Reader, b net.Conn, br io.Reader, deadline time.Time) {
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = a.Close(); _ = b.Close() })
	defer stop()
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(b, ar); _ = b.Close(); _ = a.Close(); done <- struct{}{} }()
	_, _ = io.Copy(a, br)
	_ = a.Close()
	_ = b.Close()
	<-done
}

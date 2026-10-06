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
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
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
	foreignPeer   atomic.Bool // set once a non-paired address has connected
	// pgTLS, with a broker-issued certificate, answers a PostgreSQL client's
	// SSLRequest; its listeners are then plain TCP and refuse plaintext.
	pgTLS *tls.Config
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
	if pair.client != nil {
		defer pair.client.CloseIdleConnections()
	}
	if e = pair.check(parent, ""); e != nil {
		return e
	}
	audit, e := newAudit(c)
	if e != nil {
		return e
	}
	defer func() {
		if !audit.stdout {
			_ = audit.file.Close()
		}
	}()
	ctx, cancel := context.WithDeadline(parent, c.Deadline)
	defer cancel()
	limit := maxConnections
	if c.Shared != nil {
		limit = c.Shared.connections()
	}
	r := &relay{config: c, pair: pair, audit: audit, ctx: ctx, cancel: cancel, slots: make(chan struct{}, limit)}
	if pair.cache != nil {
		// Admit nothing until every agent namespace has been listed.
		cacheDone := make(chan struct{})
		go func() { defer close(cacheDone); pair.cache.run(ctx) }()
		defer func() { cancel(); <-cacheDone }()
		synced, stop := context.WithTimeout(ctx, 30*time.Second)
		e := pair.cache.waitSynced(synced)
		stop()
		if e != nil {
			return errDenied
		}
	}
	var tlsConfig *tls.Config
	// A shared proxy without a certificate serves plaintext on the Pod
	// network; its upstreams to the broker are TLS regardless.
	if !c.Self && c.TLSCertFile != "" {
		cert, e := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if e != nil {
			return errConfig
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	}
	// A broker-issued certificate is obtained before any listener binds,
	// then renewed in the background for as long as the proxy runs.
	certDone := make(chan struct{})
	close(certDone)
	if c.TLS != nil {
		serving := newServingCert(c.TLS, c.Connect.Upstream)
		serving.issued = func(time.Time, time.Time) { _ = r.record("tls", "certificate-issued") }
		if serving.obtain(ctx) != nil {
			return errDenied
		}
		tlsConfig, r.pgTLS = serving.serverTLS("http/1.1"), serving.serverTLS("postgresql")
		certDone = make(chan struct{})
		go func() { defer close(certDone); serving.run(ctx) }()
	}
	defer func() { cancel(); <-certDone }()
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
	listenerSlots := make(chan struct{}, limit)
	bindAs := func(address string, outer *tls.Config) (net.Listener, error) {
		plain, e := net.Listen("tcp", address)
		if e != nil {
			return nil, e
		}
		var l net.Listener = &boundedListener{Listener: plain, slots: listenerSlots}
		if outer != nil {
			l = tls.NewListener(l, outer)
		}
		listeners = append(listeners, l)
		return l, nil
	}
	bind := func(address string) (net.Listener, error) { return bindAs(address, tlsConfig) }
	// A PostgreSQL listener with a broker-issued certificate starts in TCP and
	// upgrades on the client's SSLRequest.
	bindPostgres := func(address string) (net.Listener, error) {
		if r.pgTLS != nil {
			return bindAs(address, nil)
		}
		return bind(address)
	}
	failures := make(chan error, 4+len(c.postgresBindings()))
	var start []func()
	startHTTP := func(l net.Listener, h http.Handler) {
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
	serveHTTP := func(l net.Listener, h http.Handler) {
		start = append(start, func() { startHTTP(l, h) })
	}
	if c.Connect != nil {
		l, e := bind(c.Connect.Listen)
		if e != nil {
			return errConfig
		}
		serveHTTP(l, http.HandlerFunc(r.connect))
	}
	if c.AdminListen != "" && pair.cache != nil {
		// Plaintext and outside the connection slots: it serves one read-only
		// report, and its network policy admits only the janitor.
		l, e := net.Listen("tcp", c.AdminListen)
		if e != nil {
			return errConfig
		}
		listeners = append(listeners, l)
		serveHTTP(l, pair.cache.activity.handler())
	}
	servePostgres := func(l net.Listener, handle func(net.Conn)) {
		start = append(start, func() {
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
						handle(conn)
					}()
				}
			}()
		})
	}
	for _, binding := range c.postgresBindings() {
		l, e := bindPostgres(binding.Listen)
		if e != nil {
			return errConfig
		}
		servePostgres(l, func(conn net.Conn) { r.postgres(conn, binding, nil) })
	}
	if pl := c.PostgresListener; pl != nil {
		l, e := bindPostgres(pl.Listen)
		if e != nil {
			return errConfig
		}
		catalog := make(map[string]bool, len(pl.Databases))
		for _, name := range pl.Databases {
			catalog[name] = true
		}
		binding := pl.route("")
		servePostgres(l, func(conn net.Conn) { r.postgres(conn, binding, catalog) })
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
	// Admit nothing until every configured listener and browser policy is ready.
	for _, launch := range start {
		launch()
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
	if r.pair.cache != nil {
		a, ok := r.pair.attestation(peer)
		if !ok {
			return errDenied
		}
		if e := r.audit.recordAgent(protocol, "admitted", &a); e != nil {
			r.cancel()
			return e
		}
		r.pair.cache.activity.seen(a, time.Now())
		return nil
	}
	return r.record(protocol, "admitted")
}

// attest returns, in shared mode, the encoded attestation of the agent Pod at
// peer and its UID. Outside shared mode it returns empty strings and no error.
func (r *relay) attest(peer string) (encoded string, agent agentIdentity, err error) {
	if r.pair.cache == nil {
		return "", agent, nil
	}
	a, ok := r.pair.attestation(peer)
	if !ok {
		return "", agent, errDenied
	}
	if encoded, err = workloadidentity.EncodeAttestation(a); err != nil {
		return "", agent, errDenied
	}
	return encoded, agentIdentity{pod: a.PodUID, owner: a.OwnerUID, requester: a.Requester}, nil
}

// agentIdentity is the Pod and controller UIDs, and the requester, a
// connection was admitted for.
type agentIdentity struct{ pod, owner, requester string }

// watchPeer, in shared mode, rechecks the connection's agent Pod every
// second and calls end once it is no longer the same admissible Pod under the
// same controller and requester: deleted, its Sandbox gone or replaced, past
// its deadline, or its watch down. The returned function stops the watch.
func (r *relay) watchPeer(peer string, admitted agentIdentity, end func()) func() {
	if r.pair.cache == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pairInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-r.ctx.Done():
				end()
				return
			case <-ticker.C:
				a, ok := r.pair.attestation(peer)
				if !ok || a.PodUID != admitted.pod || a.OwnerUID != admitted.owner || a.Requester != admitted.requester {
					end()
					return
				}
				// An open connection is use: the janitor never retires a Sandbox mid-session.
				r.pair.cache.activity.seen(a, time.Now())
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
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

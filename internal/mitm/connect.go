package mitm

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// mitmIPKey is the rate-limit key for the per-IP flood gate shared by
// the CONNECT and absolute-form forward-proxy paths. X-Forwarded-For
// doesn't exist at this layer (the HTTP request is tunnelled or sent
// over the proxy connection); only the direct peer IP is
// meaningful. CONNECT and forward share one budget — a peer is one peer
// regardless of which ingress shape they use.
func mitmIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	return "mitm:" + host
}

// isLoopbackPeer reports whether the HTTP request came from a loopback
// peer (127.0.0.0/8 or ::1). Used to skip the CONNECT flood gate for
// local `vault run` clients — a single agent legitimately opens dozens
// of CONNECTs (one per distinct upstream host) on startup, and a
// cooperating or higher-privilege local process can trivially DoS the
// proxy by other means regardless, so rate-limiting loopback only
// breaks legitimate agents without adding defense.
func isLoopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleConnect terminates a CONNECT tunnel and serves HTTP/1.1 off the
// resulting TLS connection. The upstream target is taken from the
// CONNECT request line (r.Host) and captured in a closure so subsequent
// Host-header rewrites by the client cannot redirect the tunnel.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Count pending authentication and the whole tunnel lifetime. The actor
	// request limit inside a tunnel does not bound idle TLS connections.
	if p.strictCredentialProxy {
		select {
		case p.strictTunnels <- struct{}{}:
			defer func() { <-p.strictTunnels }()
		default:
			p.strictUnauthenticatedDeny(w, r, http.StatusTooManyRequests)
			return
		}
	}

	// Read-only pre-gate: if this IP has exhausted its auth-failure
	// budget, reject immediately. Only auth failures are recorded
	// (below) so legitimate agents don't burn the budget. Loopback
	// is exempt — see isLoopbackPeer.
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			if p.strictCredentialProxy {
				p.strictUnauthenticatedDeny(w, r, http.StatusTooManyRequests)
				return
			}
			ratelimit.WriteDenial(w, d, "Too many CONNECT attempts")
			return
		}
	}

	target := r.Host
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	port, portErr := strconv.Atoi(portStr)
	if p.strictCredentialProxy && (portErr != nil || port < 1 || port > 65535) {
		p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
		return
	}
	if !isValidHost(host) {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Authenticate the CONNECT request via Proxy-Authorization and resolve
	// the target vault. All error responses must be written BEFORE the
	// connection is hijacked — once hijacked, no HTTP status can be sent.
	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		p.recordAuthFailure(r)
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusProxyAuthRequired)
			return
		}
		writeProxyAuthChallenge(w, "Proxy-Authorization required")
		return
	}
	peer, peerErr := peerFromContext(r.Context())
	// The runner session token, set by the sidecar on CONNECT only; requests
	// inside the tunnel cannot supply or replace it.
	session := r.Header.Get(SessionHeader)
	// A shared proxy's attestation of the agent Pod, on CONNECT only; the
	// Attestor accepts it from a proxy binding alone.
	attested := brokercore.WithAttestation(r.Context(), r.Header.Get(brokercore.AttestationHeader))
	connectScope, err := p.resolveScope(attested, token, hint, peer, peerErr, false)
	if err != nil {
		p.recordAuthFailure(r)
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusForbidden)
			return
		}
		writeAuthError(w, err)
		return
	}
	// With a catalog, refuse an unlisted host before minting a certificate
	// for it or opening a tunnel.
	if p.strictCredentialProxy && p.adapter.valid() && !p.adapter.Catalog.Current().HasHost(host, port) {
		p.adapterDeny(w, auditchain.Event{Pool: connectScope.Pool, Agent: connectScope.AgentID, PodUID: connectScope.WorkloadID}, http.StatusForbidden, "unlisted")
		return
	}

	// A replica shutting down takes no new tunnels; the client retries on
	// another one.
	release, ok := p.reserveTunnel()
	if !ok {
		w.Header().Set("Connection", "close")
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "proxy shutting down", http.StatusServiceUnavailable)
		return
	}
	defer release()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = host
			}
			return p.ca.MintLeaf(sni)
		},
	}

	tlsConn := tls.Server(clientConn, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// err may carry TLS alert detail from the client — diagnostic, not secret.
		if !p.strictCredentialProxy {
			p.logger.Warn("mitm TLS handshake failed", "host", host, "err", err.Error())
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	// Serve HTTP/1.1 requests off the terminated TLS connection. The
	// listener yields the connection once, then blocks until Close so
	// http.Serve stays alive while the connection goroutine is active.
	// ConnState tracks when the connection leaves the hijacked state and
	// closes the listener so Serve returns.
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A tunnel can outlive its token or grant. Recheck each request
			// against the original proxy identity before injecting credentials.
			scope, err := p.resolveScope(brokercore.WithAttestation(r.Context(), brokercore.AttestationFrom(attested)), token, hint, peer, peerErr, true)
			if err != nil {
				w.Header().Set("Connection", "close")
				if p.strictCredentialProxy {
					p.strictUnauthenticatedDeny(w, r, http.StatusForbidden)
					return
				}
				writeAuthError(w, err)
				return
			}
			r.Header.Del(SessionHeader)
			r.Header.Del(brokercore.AttestationHeader)
			p.forwardHandler(target, host, port, scope).ServeHTTP(w, r.WithContext(withSessionToken(r.Context(), session)))
		}),
		// ReadHeaderTimeout and ReadTimeout bound the request side
		// (slow-loris defense). IdleTimeout caps keep-alives between
		// requests. The upstream transport's ResponseHeaderTimeout
		// (5 min) prevents stalled upstreams. WriteTimeout is 30 min
		// to allow long-running streaming transfers (git clone, SSE).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ConnState: func(c net.Conn, state http.ConnState) {
			// Either terminal state means Serve should return. The
			// underlying conn is owned by http.Server (Closed) or by
			// the hijack handler (Hijacked); we must not close it here.
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	// The identity check runs at connect and per request; a tunnel, including a
	// response still streaming, must not outlive the worker Pod's deadline.
	if !connectScope.NotAfter.IsZero() {
		deadline := time.AfterFunc(time.Until(connectScope.NotAfter), func() { _ = tlsConn.Close() })
		defer deadline.Stop()
	}
	defer p.trackTunnel(srv)()
	_ = srv.Serve(listener)
	// Serve can stop before taking the connection (a forced close during
	// shutdown); nothing else owns it then.
	select {
	case c := <-listener.yield:
		_ = c.Close()
	default:
	}
}

// recordAuthFailure records one auth-failure event against the per-IP
// TierAuth budget so the read-only pre-gate in handleConnect /
// handleForward will reject subsequent requests once the budget is
// exhausted. Only called on auth failure — successful requests skip
// TierAuth entirely (TierProxy covers them). Loopback peers are exempt.
func (p *Proxy) recordAuthFailure(r *http.Request) {
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		p.rateLimit.Allow(ratelimit.TierAuth, mitmIPKey(r))
	}
}

// writeProxyAuthChallenge writes a 407 with a Proxy-Authenticate header so
// well-behaved clients re-issue the CONNECT with credentials.
func writeProxyAuthChallenge(w http.ResponseWriter, msg string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="agent-vault"`)
	http.Error(w, msg, http.StatusProxyAuthRequired)
}

// writeAuthError maps a brokercore session-resolution error to an HTTP
// response at tunnel admission or before forwarding a tunneled request.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, brokercore.ErrInvalidSession):
		writeProxyAuthChallenge(w, "invalid or expired session")
	case errors.Is(err, brokercore.ErrAgentVaultAmbiguous),
		errors.Is(err, brokercore.ErrNoVaultContext):
		http.Error(w, "set vault via HTTPS_PROXY=http://<token>:<vault>@host:port", http.StatusBadRequest)
	case errors.Is(err, brokercore.ErrVaultHintMismatch),
		errors.Is(err, brokercore.ErrVaultAccessDenied):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, brokercore.ErrVaultNotFound):
		http.Error(w, "vault not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// isValidHost is a local alias for brokercore.IsValidHost so existing
// callers and the #nosec G706 justification below stay readable.
func isValidHost(h string) bool { return brokercore.IsValidHost(h) }

// oneShotListener yields a single net.Conn to http.Serve, then blocks
// Accept until Close so Serve stays alive while the connection goroutine
// handles requests.
type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

var errListenerClosed = errors.New("mitm: one-shot listener closed")

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

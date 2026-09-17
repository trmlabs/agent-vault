package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Options configures a Broker. Auth, Databases, and Leases are required; the
// rest default. The three dependencies mirror the HTTP proxy's split: identity
// (Auth), routing (Databases), and credential minting (Leases).
type Options struct {
	Auth      AgentAuthenticator
	Databases DatabaseResolver
	Leases    LeaseMinter
	Dialer    DialFunc // defaults to a plain net.Dialer; the server injects netguard's guarded dialer
	Logger    *slog.Logger

	AdmissionTimeout      time.Duration // bounded wait for global capacity (default 2s)
	AuthorizationInterval time.Duration // recheck identity and binding (default 30s)
	AuthorizationTimeout  time.Duration // fail closed if recheck stalls (default 5s)
	HandshakeTimeout      time.Duration
	StartupTimeout        time.Duration // bound on the pre-auth phase (default 5s)
	MinRenewInterval      time.Duration // floor on the renew cadence (default 5s)
	MaxConns              int           // cap on concurrent SERVING connections = upstream DB connections (default 50)
	MaxPendingConns       int           // cap on accepted-but-not-yet-serving connections (default 512)
	MaxLeasesPerActor     int           // cap on live credentials/connections per agent identity (default 16; clamped to <= MaxConns)
}

// Broker is the PostgreSQL credential-brokering TCP listener. It mirrors the
// mitm.Proxy component surface (New / Addr / Serve / Shutdown / IsListening) so
// the server owns and starts it exactly like the HTTP proxy.
type Broker struct {
	addr   string
	opts   Options
	logger *slog.Logger

	isListening atomic.Bool
	acceptSem   chan struct{} // bounds accepted (handshaking) connections
	serveSem    chan struct{} // bounds TOTAL serving connections across all databases

	cancellations  map[string]*cancelTarget
	serveMu        sync.Mutex
	upstreamCounts map[string]int // active connections by configured upstream address

	mu           sync.Mutex
	listener     net.Listener
	conns        map[net.Conn]struct{}
	leaseCounts  map[string]int // live leases per actor id
	closed       bool
	ctx          context.Context
	cancel       context.CancelFunc
	shutdownDone chan struct{}
	wg           sync.WaitGroup
}

// New builds a Broker bound to addr (host:port). It does not listen until Serve
// is called, so the server can bind the port itself and fail fast.
func New(addr string, opts Options) *Broker {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Dialer == nil {
		dialer := &net.Dialer{}
		opts.Dialer = dialer.DialContext
	}
	if opts.AdmissionTimeout <= 0 {
		opts.AdmissionTimeout = 2 * time.Second
	}
	if opts.AuthorizationInterval <= 0 {
		opts.AuthorizationInterval = 30 * time.Second
	}
	if opts.AuthorizationTimeout <= 0 {
		opts.AuthorizationTimeout = 5 * time.Second
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = defaultHandshakeTimeout
	}
	if opts.StartupTimeout <= 0 {
		opts.StartupTimeout = defaultStartupTimeout
	}
	if opts.MinRenewInterval <= 0 {
		opts.MinRenewInterval = defaultMinRenewInterval
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = defaultMaxConns
	}
	if opts.MaxPendingConns <= 0 {
		opts.MaxPendingConns = defaultMaxPendingConns
	}
	if opts.MaxLeasesPerActor <= 0 {
		opts.MaxLeasesPerActor = defaultMaxLeasesPerActor
	}
	if opts.MaxLeasesPerActor > opts.MaxConns {
		// A per-actor limit above the global ceiling has no effect.
		opts.MaxLeasesPerActor = opts.MaxConns
	}
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- Broker.Shutdown owns cancellation.
	return &Broker{
		addr:           addr,
		cancellations:  make(map[string]*cancelTarget),
		opts:           opts,
		logger:         opts.Logger,
		acceptSem:      make(chan struct{}, opts.MaxPendingConns),
		serveSem:       make(chan struct{}, opts.MaxConns),
		upstreamCounts: make(map[string]int),
		ctx:            ctx,
		cancel:         cancel,
		shutdownDone:   make(chan struct{}),
		conns:          make(map[net.Conn]struct{}),
		leaseCounts:    make(map[string]int),
	}
}

// Addr returns the configured listen address.
func (b *Broker) Addr() string { return b.addr }

// IsListening reports whether the accept loop is currently running.
func (b *Broker) IsListening() bool { return b.isListening.Load() }

// Serve accepts connections on l until Shutdown is called or Accept fails. It
// takes ownership of l. Accepted connections are capped at MaxPendingConns;
// connections beyond that are rejected immediately rather than queued. The
// smaller serving cap (MaxConns) is applied later, after authentication.
func (b *Broker) Serve(l net.Listener) error {
	// This listener exchanges bearer tokens without TLS. Enforce the transport
	// boundary here as well as in CLI configuration.
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		_ = l.Close()
		return fmt.Errorf("postgres broker requires a loopback TCP listener")
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = l.Close()
		return net.ErrClosed
	}
	b.listener = l
	b.mu.Unlock()

	b.isListening.Store(true)
	defer b.isListening.Store(false)

	for {
		conn, err := l.Accept()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		select {
		case b.acceptSem <- struct{}{}:
		default:
			b.logger.Warn("pgproxy: max pending connections reached; rejecting connection",
				slog.Int("max_pending", b.opts.MaxPendingConns))
			_ = conn.Close()
			continue
		}
		// Register and increment under the same lock used by Shutdown, before
		// launching a handler. Shutdown cannot miss a just-accepted socket.
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			<-b.acceptSem
			_ = conn.Close()
			return nil
		}
		b.conns[conn] = struct{}{}
		b.wg.Add(1)
		b.mu.Unlock()
		go func() {
			defer b.wg.Done()
			defer b.unregister(conn)
			releasePending := sync.OnceFunc(func() { <-b.acceptSem })
			defer releasePending()
			b.handleConn(conn, releasePending)
		}()
	}
}

// Shutdown stops accepting, closes all live connections (which unblocks their
// relays and triggers per-connection lease revocation), and waits for handlers
// to finish or ctx to expire.
func (b *Broker) Shutdown(ctx context.Context) error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.cancel()
		if b.listener != nil {
			_ = b.listener.Close()
		}
		for conn := range b.conns {
			_ = conn.Close()
		}
		go func() { b.wg.Wait(); close(b.shutdownDone) }()
	}
	b.mu.Unlock()
	select {
	case <-b.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Broker) unregister(conn net.Conn) {
	b.mu.Lock()
	delete(b.conns, conn)
	b.mu.Unlock()
}

// acquireLeaseSlot reserves one live-lease slot for actorID, returning false
// when the actor already holds MaxLeasesPerActor. This caps credential
// amplification: one token cannot mint unbounded dynamic DB users.
func (b *Broker) acquireLeaseSlot(actorID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.leaseCounts[actorID] >= b.opts.MaxLeasesPerActor {
		return false
	}
	b.leaseCounts[actorID]++
	return true
}

func (b *Broker) releaseLeaseSlot(actorID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.leaseCounts[actorID] > 0 {
		b.leaseCounts[actorID]--
	}
	if b.leaseCounts[actorID] == 0 {
		delete(b.leaseCounts, actorID)
	}
}

// acquireServeSlot reserves one serving slot (one upstream DB connection),
// waiting only within ctx while completed sessions finish revocation. Callers
// retain a pending slot, so this wait never creates an unbounded queue.
func (b *Broker) acquireServeSlot(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case b.serveSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *Broker) releaseServeSlot() { <-b.serveSem }

// Budgets are read on each admission; a lower live limit prevents new
// connections until occupancy falls below it. Counters disappear when drained.
func (b *Broker) acquireUpstreamSlot(svc *DatabaseService) bool {
	b.serveMu.Lock()
	defer b.serveMu.Unlock()
	limit := svc.MaxConns
	if limit <= 0 || limit > b.opts.MaxConns {
		limit = b.opts.MaxConns
	}
	if b.upstreamCounts[svc.Addr] >= limit {
		return false
	}
	b.upstreamCounts[svc.Addr]++
	return true
}

func (b *Broker) releaseUpstreamSlot(svc *DatabaseService) {
	b.serveMu.Lock()
	defer b.serveMu.Unlock()
	b.upstreamCounts[svc.Addr]--
	if b.upstreamCounts[svc.Addr] == 0 {
		delete(b.upstreamCounts, svc.Addr)
	}
}

// handleConn runs one agent connection: authenticate the agent, resolve its
// database service, mint a dynamic credential, authenticate upstream on the
// agent's behalf, then relay. The credential is revoked when the connection
// ends. A panic is contained here so one connection can never crash the shared
// server process.
func (b *Broker) handleConn(conn net.Conn, releasePending func()) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("pgproxy: recovered from panic in connection handler",
				slog.Any("panic", r))
			_ = conn.Close()
		}
	}()
	defer func() { _ = conn.Close() }()

	clientReader := &messageReader{reader: conn, startup: true}
	backend := pgproto3.NewBackend(clientReader, conn)
	backend.SetMaxBodyLen(maxAuthMessageBytes)

	// Pre-auth phase: a short deadline so a client that opens a socket and stalls
	// is dropped quickly and cannot pin resources (half-open flood).
	startupCtx, startupCancel := context.WithTimeout(b.ctx, b.opts.StartupTimeout)
	_ = conn.SetDeadline(time.Now().Add(b.opts.StartupTimeout))

	startup, err := readStartup(backend, conn)
	if err != nil {
		var request *cancelRequestError
		if errors.As(err, &request) {
			b.cancelQuery(startupCtx, request.request)
		}
		startupCancel()
		if !errors.Is(err, errCancelRequest) {
			b.logger.Debug("pgproxy: startup failed", slog.String("error", err.Error()))
		}
		return
	}
	clientReader.startup = false
	requestedDB := startup.Parameters["database"]
	if requestedDB == "" {
		requestedDB = startup.Parameters["user"]
	}

	scope, token, err := authenticateAgent(startupCtx, backend, b.opts.Auth, startup)
	startupCancel()
	if err != nil || scope == nil || scope.VaultID == "" || scope.ActorID == "" {
		if err == nil {
			err = fmt.Errorf("incomplete agent scope")
		}
		b.logger.Warn("pgproxy: agent authentication failed", slog.String("error", err.Error()))
		writeClientError(backend, "28000", "Agent Vault: authentication failed")
		return
	}

	// Authenticated: a longer budget for the mint + upstream-connect phase, which
	// can be slow when role DDL serializes at scale.
	hsCtx, cancel := context.WithTimeout(b.ctx, b.opts.HandshakeTimeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(b.opts.HandshakeTimeout))

	// Cap live credentials per agent identity before minting (fail closed).
	if !b.acquireLeaseSlot(scope.ActorID) {
		b.logger.Warn("pgproxy: per-actor live-credential limit reached",
			slog.String("vault", scope.VaultID),
			slog.String("actor", scope.ActorID),
			slog.Int("limit", b.opts.MaxLeasesPerActor))
		writeClientError(backend, "53300", "Agent Vault: too many concurrent database sessions")
		return
	}
	defer b.releaseLeaseSlot(scope.ActorID)

	// Global backstop: bound the total upstream connections across all databases,
	// applied only after auth so unauthenticated handshakes cannot consume it.
	admissionCtx, admissionCancel := context.WithTimeout(hsCtx, b.opts.AdmissionTimeout)
	admitted := b.acquireServeSlot(admissionCtx)
	admissionCancel()
	if !admitted {
		b.logger.Warn("pgproxy: serving-connection limit reached",
			slog.String("vault", scope.VaultID),
			slog.Int("max_conns", b.opts.MaxConns))
		writeClientError(backend, "53300", "Agent Vault: too many concurrent database connections")
		return
	}
	defer b.releaseServeSlot()
	releasePending()

	svc, err := b.opts.Databases.ResolveDatabase(hsCtx, *scope, requestedDB)
	if err != nil {
		b.logger.Warn("pgproxy: database service resolution failed",
			slog.String("vault", scope.VaultID),
			slog.String("database", requestedDB),
			slog.String("error", err.Error()))
		writeClientError(backend, "3D000", fmt.Sprintf("Agent Vault: no database service for %q", requestedDB))
		return
	}

	// Per-database budget: bound the connections to THIS upstream so a burst to
	// one database cannot starve the others behind the same broker. Applied
	// before minting so a rejected connection wastes no Vault role.
	if !b.acquireUpstreamSlot(svc) {
		b.logger.Warn("pgproxy: per-database connection limit reached",
			slog.String("vault", scope.VaultID),
			slog.String("service", svc.Name),
			slog.String("upstream", svc.Addr))
		writeClientError(backend, "53300", "Agent Vault: too many concurrent connections to this database")
		return
	}
	defer b.releaseUpstreamSlot(svc)

	lease, err := b.opts.Leases.Mint(hsCtx, scope.VaultID, svc)
	if err != nil {
		b.logger.Error("pgproxy: credential minting failed",
			slog.String("vault", scope.VaultID),
			slog.String("service", svc.Name),
			slog.String("error", err.Error()))
		writeClientError(backend, "08006", "Agent Vault: could not obtain a database credential")
		return
	}
	// Once minted, the credential must be revoked when this connection ends.
	if lease == nil {
		writeClientError(backend, "08006", "Agent Vault: invalid database lease")
		return
	}
	defer func() {
		revokeCtx, revokeCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer revokeCancel()
		if err := b.opts.Leases.Revoke(revokeCtx, lease.ID); err != nil {
			b.logger.Warn("pgproxy: lease revoke failed",
				slog.String("service", svc.Name),
				slog.String("error", err.Error()))
		}
	}()

	if lease.ID == "" || lease.Username == "" || lease.Password == "" || !lease.ExpiresAt.After(time.Now()) {
		writeClientError(backend, "08006", "Agent Vault: invalid database lease")
		return
	}
	// Never finish a slow handshake using a credential that has expired.
	leaseCtx, leaseCancel := context.WithDeadline(hsCtx, lease.ExpiresAt)
	defer leaseCancel()
	upstream, err := connectUpstream(leaseCtx, b.opts.Dialer, svc, lease, startup.Parameters)
	if err != nil {
		b.logger.Error("pgproxy: upstream connection failed",
			slog.String("service", svc.Name),
			slog.String("upstream", svc.Addr),
			slog.String("error", err.Error()))
		writeClientError(backend, "08006", "Agent Vault: could not connect to the database")
		return
	}
	defer func() { _ = upstream.conn.Close() }()

	if leaseCtx.Err() != nil || !lease.ExpiresAt.After(time.Now()) {
		return
	}
	deadline, _ := leaseCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	unregisterCancel, err := b.registerCancel(upstream, svc)
	if err != nil {
		return
	}
	defer unregisterCancel()
	if err := sendClientReady(backend, upstream); err != nil {
		b.logger.Debug("pgproxy: completing agent handshake failed", slog.String("error", err.Error()))
		return
	}
	// Handshake complete: clear the deadline and let the relay run unbounded.
	_ = conn.SetDeadline(time.Time{})
	cancel()

	// lease.ID is the join key that links this Agent Vault actor to the Vault
	// audit record (which maps lease -> minted DB username -> role). It is an
	// identifier, not a credential. The password and username are never logged.
	b.logger.Info("pgproxy: session established",
		slog.String("vault", scope.VaultID),
		slog.String("actor", scope.ActorID),
		slog.String("service", svc.Name),
		slog.String("upstream", svc.Addr),
		slog.String("lease", lease.ID))

	relayCtx, relayCancel := context.WithCancel(b.ctx)
	defer relayCancel()
	terminate := func() {
		_ = conn.Close()
		_ = upstream.conn.Close()
	}
	authorizationDone := make(chan struct{})
	go func() {
		defer close(authorizationDone)
		b.authorizationLoop(relayCtx, token, startup.Parameters["agent_vault_vault"], requestedDB, *scope, *svc, terminate)
	}()
	defer func() { relayCancel(); <-authorizationDone }()
	renewDone := make(chan struct{})
	go func() { defer close(renewDone); b.renewLoop(relayCtx, lease, svc, terminate) }()
	defer func() { relayCancel(); <-renewDone }()

	relay(conn, upstream.conn)
}

// renewLoop keeps the lease alive for the life of the connection and enforces
// the credential's expiry on the session. While the lease is renewable it is
// extended before expiry so an in-flight session is not interrupted. When the
// lease can no longer be extended — renewal fails, Vault refuses to extend past
// max TTL, or the lease was never renewable — the session must not outlive its
// credential: the loop waits until the last known expiry and terminates the
// connection, ending the relay and triggering revocation. This makes
// "short-lived" and the revocation kill switch bind for the whole session, not
// just at connect time.
func (b *Broker) renewLoop(ctx context.Context, lease *Lease, svc *DatabaseService, terminate func()) {
	// The watchdog is independent of Vault I/O and also cancels any in-flight
	// renewal. A late response must never resurrect an expired session.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	expiry := lease.ExpiresAt
	if !expiry.After(time.Now()) {
		terminate()
		return
	}
	expire := func() {
		b.logger.Warn("pgproxy: credential expired; terminating session", "service", svc.Name)
		terminate()
		cancel()
	}
	watchdog := time.AfterFunc(time.Until(expiry), expire)
	defer watchdog.Stop()
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("pgproxy: renewal panic; terminating session")
			expire()
		}
	}()
	increment := time.Until(expiry)
	if increment < b.opts.MinRenewInterval {
		increment = b.opts.MinRenewInterval
	}
	for lease.Renewable {
		remaining := time.Until(expiry)
		wait := remaining - remaining/renewLeadFraction
		if wait < b.opts.MinRenewInterval {
			wait = b.opts.MinRenewInterval
		}
		// If the cadence floor would pass expiry, let the watchdog terminate.
		if wait >= remaining {
			break
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		renewCtx, renewCancel := context.WithDeadline(ctx, expiry)
		next, err := b.opts.Leases.Renew(renewCtx, lease.ID, increment)
		renewCancel()
		if err != nil {
			if ctx.Err() == nil {
				b.logger.Warn("pgproxy: renewal failed; retaining confirmed expiry", "service", svc.Name, "error", err)
			}
			break
		}
		if !next.After(expiry) {
			break
		}
		if ctx.Err() != nil || !time.Now().Before(expiry) || !watchdog.Stop() {
			expire()
			return
		}
		expiry = next
		watchdog.Reset(time.Until(expiry))
	}
	<-ctx.Done()
}

// relay splices two connections until either side closes, then tears both down
// so the surviving copy unblocks. Bytes flow verbatim, so the full protocol
// (simple and extended query, COPY, etc.) passes through untouched.
func relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

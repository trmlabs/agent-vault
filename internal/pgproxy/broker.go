package pgproxy

import (
	"net/netip"

	"context"
	"errors"
	"fmt"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
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
	MaxLeasesPerActor     int           // cap on live credentials/connections per workload (Pod), or per agent when no workload is known (default 16; clamped to <= MaxConns)
	// MaxLeasesPerAgent caps one agent's sessions across all its workloads on
	// this replica, so a pool agent with many Pods cannot take the whole
	// serving cap (default MaxConns minus MaxLeasesPerActor, at least
	// MaxLeasesPerActor; clamped to <= MaxConns).
	MaxLeasesPerAgent int
	// TrustProxyHeader reads a PROXY v1 header from the in-Pod loopback TLS
	// terminator on every connection and uses its source as the peer address.
	TrustProxyHeader bool
	// Sessions, when set, caps live sessions per Pod across every broker replica.
	Sessions SessionLedger
	Pool     *PoolOptions // transaction-mode multiplexing; nil keeps one upstream connection per session
	Audit    AuditTrail   // signed audit trail; nil disables it
}

// Broker is the PostgreSQL credential-brokering TCP listener. It mirrors the
// mitm.Proxy component surface (New / Addr / Serve / Shutdown / IsListening) so
// the server owns and starts it exactly like the HTTP proxy.
type Broker struct {
	addr   string
	opts   Options
	logger *slog.Logger

	isListening atomic.Bool
	// authorityLost records a stop forced by the cleanup journal, so Serve
	// reports it and the process restarts as a new owner.
	authorityLost atomic.Bool
	acceptSem     chan struct{} // bounds accepted (handshaking) connections
	serveSem      chan struct{} // bounds TOTAL serving connections across all databases

	cancellations  map[string]*cancelTarget
	serveMu        sync.Mutex
	upstreamCounts map[string]int // active connections by configured upstream address

	mu                   sync.Mutex
	listener             net.Listener
	conns                map[net.Conn]struct{}
	connActors           map[net.Conn]runtimestatus.Attribution // authenticated actor and instance; absent means unattributed
	connectionGeneration uint64
	leaseCounts          map[string]int // live leases per actor id
	leaseChanged         chan struct{}  // wakes bounded admissions after cleanup
	closed               bool
	ctx                  context.Context
	cancel               context.CancelFunc
	shutdownDone         chan struct{}
	wg                   sync.WaitGroup
	pools                *serverPools // nil unless Options.Pool is set
	pooled               map[net.Conn]*pooledSession
	closers              map[net.Conn]func(closeNotice) // unpooled sessions that can end with a notice
	denied               deniedLimiter
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
	maxConns, perActor := defaultMaxConns, defaultMaxLeasesPerActor
	if opts.Pool != nil {
		maxConns, perActor = defaultPooledMaxConns, defaultPooledMaxLeasesPerActor
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = maxConns
	}
	if opts.MaxPendingConns <= 0 {
		// Handshakes in progress scale with the serving cap they feed.
		opts.MaxPendingConns = max(defaultMaxPendingConns, opts.MaxConns)
	}
	if opts.MaxLeasesPerActor <= 0 {
		opts.MaxLeasesPerActor = perActor
	}
	if opts.MaxLeasesPerActor > opts.MaxConns {
		// A per-actor limit above the global ceiling has no effect.
		opts.MaxLeasesPerActor = opts.MaxConns
	}
	if opts.MaxLeasesPerAgent <= 0 {
		// Leave another agent at least one workload's worth of the cap.
		opts.MaxLeasesPerAgent = max(opts.MaxConns-opts.MaxLeasesPerActor, opts.MaxLeasesPerActor)
	}
	opts.MaxLeasesPerAgent = min(opts.MaxLeasesPerAgent, opts.MaxConns)
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- Broker.Shutdown owns cancellation.
	b := &Broker{
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
		connActors:     make(map[net.Conn]runtimestatus.Attribution),
		leaseCounts:    make(map[string]int),
		leaseChanged:   make(chan struct{}),
		pooled:         make(map[net.Conn]*pooledSession),
		closers:        make(map[net.Conn]func(closeNotice)),
	}
	if opts.Pool != nil {
		pool := *opts.Pool
		if live, ok := opts.Leases.(interface{ LiveReplicas() int }); ok && pool.LiveReplicas == nil {
			pool.LiveReplicas = live.LiveReplicas
		}
		b.pools = newServerPools(b, pool)
	}
	return b
}

// ErrAuthorityLost reports that the broker stopped because its cleanup
// authority ended: this replica fenced itself or lost its owner row.
var ErrAuthorityLost = errors.New("postgres broker stopped: database cleanup authority lost")

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
	b.watchAudit()
	if leases, ok := b.opts.Leases.(interface{ AuthorityDone() <-chan struct{} }); ok {
		go func() {
			select {
			case <-leases.AuthorityDone():
				if b.ctx.Err() != nil {
					return
				}
				b.logger.Error("pgproxy: durable cleanup authority unavailable; stopping broker")
				b.authorityLost.Store(true)
				ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
				defer cancel()
				// A drain already under way would keep serving on credentials
				// other replicas may have claimed and revoked: end it now.
				b.forceClose()
				_ = b.Shutdown(ctx)
			case <-b.ctx.Done():
			}
		}()
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				if b.authorityLost.Load() {
					return ErrAuthorityLost
				}
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
			if b.authorityLost.Load() {
				return ErrAuthorityLost
			}
			return nil
		}
		b.conns[conn] = struct{}{}
		b.connectionGeneration++
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

// drainReserve is the part of Shutdown's budget kept for revoking pooled
// credentials after draining sessions.
const drainReserve = leaseRevokeTimeout

// Shutdown stops accepting, closes all live connections (which unblocks their
// relays and triggers per-connection lease revocation), and waits for handlers
// to finish or ctx to expire. With PoolOptions.DrainSessions, pooled sessions
// instead end at their next idle point, and only those still busy when ctx is
// within drainReserve of its deadline are closed. A stop forced by lost
// cleanup authority never drains.
func (b *Broker) Shutdown(ctx context.Context) error {
	var draining []*pooledSession
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		drain := b.opts.Pool != nil && b.opts.Pool.DrainSessions && !b.authorityLost.Load()
		if !drain {
			b.cancel()
		}
		if b.listener != nil {
			_ = b.listener.Close()
		}
		for conn := range b.conns {
			if s := b.pooled[conn]; drain && s != nil {
				draining = append(draining, s)
				continue
			}
			b.endConnLocked(conn, noticeRestarting)
		}
		if drain {
			go func() {
				force := ctx
				if deadline, ok := ctx.Deadline(); ok {
					var cancel context.CancelFunc
					force, cancel = context.WithDeadline(ctx, deadline.Add(-drainReserve))
					defer cancel()
				}
				select {
				case <-force.Done():
					b.logger.Warn("pgproxy: drain deadline reached; closing busy sessions")
					b.mu.Lock()
					for conn := range b.conns {
						b.endConnLocked(conn, noticeRestarting)
					}
					b.mu.Unlock()
				case <-b.shutdownDone:
				}
			}()
		}
		go func() {
			b.wg.Wait()
			b.cancel()
			// Sessions are gone: close idle server connections and revoke
			// pooled credentials.
			if b.pools != nil {
				b.pools.close()
			}
			close(b.shutdownDone)
		}()
	}
	b.mu.Unlock()
	for _, s := range draining {
		s.beginDrain()
	}
	select {
	case <-b.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// forceClose ends every connection now, for a stop that must not drain, such
// as lost cleanup authority while a graceful drain is running. Shutdown, if
// not yet called, then finds nothing left to drain.
func (b *Broker) forceClose() {
	b.mu.Lock()
	for conn := range b.conns {
		b.endConnLocked(conn, noticeRestarting)
	}
	b.mu.Unlock()
}

// trackPooled lists a pooled session for draining; false once Shutdown has
// begun, when the session must not start.
func (b *Broker) trackPooled(conn net.Conn, s *pooledSession) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.pooled[conn] = s
	return true
}

func (b *Broker) untrackPooled(conn net.Conn) {
	b.mu.Lock()
	delete(b.pooled, conn)
	b.mu.Unlock()
}

func (b *Broker) unregister(conn net.Conn) {
	b.mu.Lock()
	delete(b.conns, conn)
	delete(b.connActors, conn)
	b.connectionGeneration++
	b.mu.Unlock()
}

func (b *Broker) attribute(conn net.Conn, owner runtimestatus.Attribution) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.conns[conn]; ok {
		b.connActors[conn] = owner
	}
}

// acquireLeaseSlot preserves the actor credential cap while waiting for cleanup.
// The caller retains its pending slot and shares a bounded admission deadline.
func (b *Broker) acquireLeaseSlot(ctx context.Context, actorID string, limit int) bool {
	for {
		b.mu.Lock()
		if ctx.Err() != nil {
			b.mu.Unlock()
			return false
		}
		if b.leaseCounts[actorID] < limit {
			b.leaseCounts[actorID]++
			b.mu.Unlock()
			return true
		}
		changed := b.leaseChanged
		b.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

func (b *Broker) releaseLeaseSlot(actorID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.leaseCounts[actorID] > 0 {
		b.leaseCounts[actorID]--
		close(b.leaseChanged)
		b.leaseChanged = make(chan struct{})
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

	peer := netip.Addr{}
	if b.opts.TrustProxyHeader {
		_ = conn.SetDeadline(time.Now().Add(b.opts.StartupTimeout))
		source, err := brokercore.ReadProxyV1(conn, conn.RemoteAddr())
		if err != nil {
			b.logger.Debug("pgproxy: PROXY header refused")
			return
		}
		peer = source
	} else if remote, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		peer = remote.Addr().Unmap()
	}

	// The sidecar's session line, if any, precedes the startup packet.
	_ = conn.SetDeadline(time.Now().Add(b.opts.StartupTimeout))
	session, attestation, stream, err := readSessionPreamble(conn)
	if err != nil {
		b.logger.Debug("pgproxy: session preamble refused")
		return
	}
	clientReader := &messageReader{reader: stream, startup: true}
	backend := pgproto3.NewBackend(clientReader, conn)
	backend.SetMaxBodyLen(maxAuthMessageBytes)

	// Pre-auth phase: a short deadline so a client that opens a socket and stalls
	// is dropped quickly and cannot pin resources (half-open flood).
	// A shared proxy's attestation follows the connection to every identity
	// check, admission and recheck alike.
	baseCtx := brokercore.WithAttestation(b.ctx, attestation)
	startupCtx, startupCancel := context.WithTimeout(baseCtx, b.opts.StartupTimeout)
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

	scope, token, err := authenticateAgent(startupCtx, backend, b.authenticator(peer), startup)
	startupCancel()
	if err == nil && scope != nil && !brokercore.KindAdmitted(brokercore.ConnKinds(conn), scope.IdentityKind) {
		// Each listener admits only the identity kinds it was opened for.
		err, scope = fmt.Errorf("identity kind not admitted on this listener"), nil
	}
	if err != nil || scope == nil || scope.VaultID == "" || scope.ActorID == "" {
		if err == nil {
			err = fmt.Errorf("incomplete agent scope")
		}
		b.logger.Warn("pgproxy: agent authentication failed", slog.String("error", err.Error()))
		// Anyone can reach this point, so these rows are rate-limited.
		if b.denied.allow(time.Now(), b.logger) {
			// The refusing check, and for a signing-key refusal the token's
			// kid and the peer; never the token.
			event := auditchain.Event{}
			if reason := brokercore.DenialReason(err); reason != "" {
				event.Decision = "identity_" + reason
			}
			if key := brokercore.DenialKey(err); key != nil {
				event.Kid, event.KidSHA256, event.Peer = key.Kid, key.KidSHA256, key.Peer
			}
			b.auditDenied(event, "authentication")
		}
		writeClientError(backend, "28000", "authentication", "Agent Vault: authentication failed")
		return
	}
	// Audit identity comes only from the verified scope. The binding is added
	// once the database resolves.
	event := auditchain.Event{Pool: scope.Pool, Agent: scope.ActorID, PodUID: scope.WorkloadID, Session: newSessionID()}
	connCtx := WithSession(baseCtx, session)
	refuse := func(outcome, code, message string) {
		b.auditDenied(event, outcome)
		writeClientError(backend, code, outcome, message)
	}
	if err := b.auditAdmit(); err != nil {
		b.logger.Error("pgproxy: audit trail unavailable; refusing session", slog.String("error", err.Error()))
		refuse("audit_unavailable", "08004", "Agent Vault: audit unavailable")
		return
	}
	// A replica without a fresh owner row takes no new sessions: it is
	// starting, or its renewals are failing on the way to a fence.
	if ready, ok := b.opts.Leases.(interface{ Ready() bool }); ok && !ready.Ready() {
		refuse("not_ready", "57P03", "Agent Vault: broker not ready; retry")
		return
	}
	// Until now this connection counted against every actor's cleanup status.
	b.attribute(conn, runtimestatus.Attribution{ActorID: scope.ActorID, WorkloadID: scope.WorkloadID})

	// Authenticated: a longer budget for the mint + upstream-connect phase, which
	// can be slow when role DDL serializes at scale.
	hsCtx, cancel := context.WithTimeout(connCtx, b.opts.HandshakeTimeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(b.opts.HandshakeTimeout))

	// Share one admission budget across actor and global capacity.
	admissionCtx, admissionCancel := context.WithTimeout(hsCtx, b.opts.AdmissionTimeout)
	defer admissionCancel()
	// Cap live credentials per agent identity before minting (fail closed).
	// One pool agent serves many workers, so the cap applies per workload (Pod).
	capKey := scope.ActorID
	if scope.WorkloadID != "" {
		capKey = "workload:" + scope.WorkloadID
	}
	if !b.acquireLeaseSlot(admissionCtx, capKey, b.opts.MaxLeasesPerActor) {
		b.logger.Warn("pgproxy: per-workload live-credential limit reached",
			slog.String("vault", scope.VaultID),
			slog.String("actor", scope.ActorID),
			slog.String("workload", scope.WorkloadID),
			slog.Int("limit", b.opts.MaxLeasesPerActor))
		refuse("actor_limit", "53300", "Agent Vault: too many concurrent database sessions")
		return
	}
	defer b.releaseLeaseSlot(capKey)
	// A pool agent's workloads together stay under the per-agent cap, taken
	// after the workload's own so a Pod waiting at its cap holds none of it.
	if scope.WorkloadID != "" {
		agentKey := "agent:" + scope.ActorID
		if !b.acquireLeaseSlot(admissionCtx, agentKey, b.opts.MaxLeasesPerAgent) {
			b.logger.Warn("pgproxy: per-agent live-credential limit reached",
				slog.String("vault", scope.VaultID),
				slog.String("actor", scope.ActorID),
				slog.Int("limit", b.opts.MaxLeasesPerAgent))
			refuse("actor_limit", "53300", "Agent Vault: too many concurrent database sessions")
			return
		}
		defer b.releaseLeaseSlot(agentKey)
	}
	// Across the fleet, the store holds the authoritative per-Pod count; the
	// in-memory slot above only spares the store a call this replica can refuse.
	if b.opts.Sessions != nil && scope.WorkloadID != "" {
		id := newSessionID()
		sessionID := "ledger-" + id
		err := errors.New("session ID unavailable")
		if id != "" {
			err = b.opts.Sessions.Add(admissionCtx, sessionID, scope.WorkloadID, b.opts.MaxLeasesPerActor)
		}
		if errors.Is(err, ErrSessionLimit) {
			b.logger.Warn("pgproxy: per-workload live-credential limit reached across the fleet",
				slog.String("vault", scope.VaultID), slog.String("actor", scope.ActorID),
				slog.String("workload", scope.WorkloadID), slog.Int("limit", b.opts.MaxLeasesPerActor))
			refuse("actor_limit", "53300", "Agent Vault: too many concurrent database sessions")
			return
		}
		if err != nil {
			b.logger.Error("pgproxy: session ledger unavailable; refusing session", slog.String("error", err.Error()))
			refuse("ledger_unavailable", "08004", "Agent Vault: session accounting unavailable")
			return
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
			defer cancel()
			if err := b.opts.Sessions.Remove(ctx, sessionID); err != nil {
				// The row stops counting when this replica's owner row expires.
				b.logger.Warn("pgproxy: session ledger removal failed", slog.String("error", err.Error()))
			}
		}()
	}

	// Global backstop: bound the total upstream connections across all databases,
	// applied only after auth so unauthenticated handshakes cannot consume it.
	admitted := b.acquireServeSlot(admissionCtx)
	admissionCancel()
	if !admitted {
		b.logger.Warn("pgproxy: serving-connection limit reached",
			slog.String("vault", scope.VaultID),
			slog.Int("max_conns", b.opts.MaxConns))
		refuse("capacity", "53300", "Agent Vault: too many concurrent database connections")
		return
	}
	defer b.releaseServeSlot()
	releasePending()

	// Admission can wait for cleanup. Recheck the original proof before using
	// its scope to resolve a destination or issue another credential.
	checkCtx, checkCancel := context.WithTimeout(hsCtx, b.opts.AuthorizationTimeout)
	current, checkErr := b.authenticator(peer).Authenticate(checkCtx, token, startup.Parameters["agent_vault_vault"])
	valid := checkErr == nil && checkCtx.Err() == nil && current != nil &&
		current.ActorID == scope.ActorID && current.VaultID == scope.VaultID && current.WorkloadID == scope.WorkloadID
	checkCancel()
	if !valid {
		refuse("authentication", "28000", "Agent Vault: authentication failed")
		return
	}

	var who Requester
	svc, err := b.opts.Databases.ResolveDatabase(withRequesterRecord(hsCtx, &who), *scope, requestedDB)
	event.RequesterKind, event.TokenSHA256, event.RequesterOID = who.Kind, who.TokenSHA256, who.ObjectID
	event.Tier, event.Decision, event.Groups, event.CacheAgeSec = who.Tier, who.Decision, who.Groups, who.CacheAgeSec
	if who.Kind == "person" || who.Kind == "agent" {
		event.Requester = who.Subject
	}
	var refused *RefusedError
	if errors.As(err, &refused) {
		// A refusal names an entry that exists and is granted to the pool.
		event.Binding = databaseBinding(scope.VaultID, &DatabaseService{Name: requestedDB})
		b.logger.Warn("pgproxy: database refused by the authorization model",
			slog.String("vault", scope.VaultID), slog.String("database", requestedDB), slog.String("decision", refused.Outcome))
		refuse(refused.Outcome, "42501", fmt.Sprintf("Agent Vault: not authorized for database %q (%s)", requestedDB, refused.Outcome))
		return
	}
	if err != nil {
		b.logger.Warn("pgproxy: database service resolution failed",
			slog.String("vault", scope.VaultID),
			slog.String("database", requestedDB),
			slog.String("error", err.Error()))
		refuse("no_database", "3D000", fmt.Sprintf("Agent Vault: no database service for %q", requestedDB))
		return
	}
	event.Binding = databaseBinding(scope.VaultID, svc)
	if svc.ReadOnly {
		// A search path that names pg_temp first makes an unqualified
		// CREATE TABLE temporary.
		for key, value := range startup.Parameters {
			if strings.EqualFold(key, "search_path") && strings.Contains(strings.ToLower(value), "pg_temp") {
				refuse("read_only", "25006", readOnlyMessage)
				return
			}
		}
	}
	if b.pools != nil {
		// Multiplexed: the pool owns the database budget, credentials and
		// server connections, so this session takes none of its own.
		b.servePooled(hsCtx, conn, backend, *scope, svc, token, startup.Parameters["agent_vault_vault"], requestedDB, peer, startup.Parameters, event)
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
		refuse("database_limit", "53300", "Agent Vault: too many concurrent connections to this database")
		return
	}
	defer b.releaseUpstreamSlot(svc)

	lease, err := b.opts.Leases.Mint(hsCtx, *scope, svc)
	if err != nil {
		b.logger.Error("pgproxy: credential minting failed",
			slog.String("vault", scope.VaultID),
			slog.String("service", svc.Name),
			slog.String("error", err.Error()))
		refuse("credential", "08006", "Agent Vault: could not obtain a database credential")
		return
	}
	// Once minted, the credential must be revoked when this connection ends.
	if lease == nil {
		refuse("credential", "08006", "Agent Vault: invalid database lease")
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
		refuse("credential", "08006", "Agent Vault: invalid database lease")
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
		refuse("upstream", "08006", "Agent Vault: could not connect to the database")
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
	// No query may reach the database before its session row exists.
	opened := event
	opened.Event, opened.Outcome = auditchain.EventSessionOpen, "admitted"
	if err := b.auditRecord(opened); err != nil {
		b.logger.Error("pgproxy: audit trail unavailable; refusing session", slog.String("error", err.Error()))
		writeClientError(backend, "08004", "audit_unavailable", "Agent Vault: audit unavailable")
		return
	}
	defer func() {
		closed := event
		closed.Event, closed.Outcome = auditchain.EventSessionClose, "closed"
		_ = b.auditRecord(closed)
	}()
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
		slog.String("workload", scope.WorkloadID),
		slog.String("service", svc.Name),
		slog.String("upstream", svc.Addr),
		slog.String("lease", lease.ID))

	relayCtx, relayCancel := context.WithCancel(connCtx)
	defer relayCancel()
	// endWith ends the session for the broker's own reason. With a notice, the
	// database side closes first so the relay stops at a message boundary and
	// writes the notice before closing the client; the client is closed
	// regardless once the notice has had its chance.
	var notice closeState
	var endOnce sync.Once
	endWith := func(n *closeNotice) {
		endOnce.Do(func() {
			if n != nil {
				notice.notice.Store(n)
				// Stop relaying the database first, so the cancel below cannot
				// reach the client as the server's own error ahead of the notice.
				_ = upstream.conn.Close()
				time.AfterFunc(2*noticeWriteTimeout, func() { _ = conn.Close() })
			} else {
				_ = conn.Close()
			}
			// Closing a PostgreSQL socket does not necessarily interrupt a running
			// query. Send the session's private cancellation capability as well.
			if upstream.backendKey != nil {
				ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
				b.cancelQuery(ctx, &pgproto3.CancelRequest{ProcessID: upstream.backendKey.ProcessID, SecretKey: upstream.backendKey.SecretKey})
				cancel()
			}
			_ = upstream.conn.Close()
		})
	}
	terminate := func() { endWith(nil) }
	defer b.registerCloser(conn, func(n closeNotice) { endWith(&n) })()
	authorizationDone := make(chan struct{})
	go func() {
		defer close(authorizationDone)
		b.authorizationLoop(relayCtx, token, startup.Parameters["agent_vault_vault"], requestedDB, *scope, *svc, func() { endWith(&noticeAuthorization) }, peer)
	}()
	defer func() { relayCancel(); <-authorizationDone }()
	if !scope.NotAfter.IsZero() {
		// A pool Pod's session ends at its deadline, independent of any recheck.
		deadline := time.AfterFunc(time.Until(scope.NotAfter), func() { endWith(&noticeDeadline) })
		defer deadline.Stop()
	}
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		b.renewLoop(relayCtx, lease, svc, func() { endWith(&noticeCredential) })
	}()
	defer func() { relayCancel(); <-renewDone }()

	defer func() {
		if n := notice.notice.Load(); n != nil {
			sent := n
			if s := notice.sent.Load(); s != nil {
				sent = s
			}
			b.logSessionEnd(svc.Name, *sent, notice.written.Load())
		}
	}()
	if !svc.ReadOnly {
		relay(conn, upstream.conn, &notice)
		return
	}
	if refused, clean := relayReadOnly(conn, upstream.conn, &notice); refused {
		b.logger.Warn("pgproxy: statement refused on a read-only login; ending session",
			slog.String("service", svc.Name), slog.String("actor", scope.ActorID))
		b.auditDenied(event, "read_only")
		if clean {
			_ = conn.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
			writeClientError(backend, "25006", "read_only", readOnlyMessage)
		}
		terminate()
	}
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
func relay(client, upstream net.Conn, notice *closeState) {
	toClient := &frameTracker{w: client}
	fromClient, fromServer := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(fromClient)
		_, _ = io.Copy(upstream, client)
	}()
	go func() {
		defer close(fromServer)
		_, _ = io.Copy(toClient, upstream)
	}()
	select {
	case <-fromClient:
	case <-fromServer:
	}
	_ = upstream.Close()
	<-fromServer
	sendNotice(client, toClient, notice)
	_ = client.Close()
	<-fromClient
}

// sendNotice writes the session's close notice, if the broker ended it, once
// the database stream has stopped between two messages. A restart that finds
// a transaction open says so instead of claiming a clean restart.
func sendNotice(client net.Conn, toClient *frameTracker, notice *closeState) {
	n := notice.notice.Load()
	if n == nil {
		return
	}
	if *n == noticeRestarting && !toClient.idle() {
		n = &noticeRestartCut
	}
	notice.sent.Store(n)
	if toClient.atBoundary() {
		notice.written.Store(writeNotice(client, *n))
	}
}

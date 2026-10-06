package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// PoolOptions turns on transaction-mode multiplexing: client sessions share a
// small set of server connections per (worker pool, database binding) on this
// replica, each set using one Vault credential that rotates in the background.
// Nil keeps one upstream connection and credential per client session.
type PoolOptions struct {
	// Replicas divides each database's budget (the catalog's maxConns, or the
	// broker's MaxConns) between broker replicas. Default 1.
	Replicas int
	// LiveReplicas, when set and positive, replaces Replicas with the fleet's
	// current size, so budgets follow replicas joining and leaving. The
	// durable cleanup journal supplies it from live owner rows.
	LiveReplicas func() int
	// SessionShare caps, per pool key, the connections pinned to one client
	// for session state, as a fraction of the budget. Default 0.1, minimum 1.
	SessionShare float64
	// DrainSessions makes Shutdown close each client session at its next idle
	// point (no open transaction, nothing unanswered) with 57P01, and cut only
	// sessions still busy at the deadline. Off, Shutdown closes every session
	// at once.
	DrainSessions bool
	// QueueFactor bounds waiting checkouts at this multiple of the budget;
	// QueueWait bounds how long one waits. Defaults 200 and 5 seconds, so
	// 10,000 clients on a 50-connection budget queue rather than fail. A
	// waiter costs only a goroutine. Overflow and timeouts are refused with
	// SQLSTATE 53300.
	QueueFactor int
	QueueWait   time.Duration
	// RotateFraction of a credential's lifetime passes before its successor
	// is minted. Default 0.5, with up to 10% jitter per key.
	RotateFraction float64
	// IdleTimeout closes server connections unused for this long. Default 5m.
	IdleTimeout time.Duration
	// IdleInTransaction is the server's idle_in_transaction_session_timeout
	// on pooled connections: a client that holds a transaction open without
	// sending anything for this long loses its session, so it cannot sit on
	// a server connection. Default 5m.
	IdleInTransaction time.Duration
	// DefaultBudget is the server-connection budget for a database without a
	// catalog maxConns. Default 50.
	DefaultBudget int
}

func (o *PoolOptions) withDefaults() PoolOptions {
	p := *o
	if p.Replicas < 1 {
		p.Replicas = 1
	}
	if p.SessionShare <= 0 || p.SessionShare > 1 {
		p.SessionShare = 0.1
	}
	if p.QueueFactor < 1 {
		p.QueueFactor = 200
	}
	if p.QueueWait <= 0 {
		p.QueueWait = 5 * time.Second
	}
	if p.RotateFraction <= 0 || p.RotateFraction >= 1 {
		p.RotateFraction = 0.5
	}
	if p.IdleTimeout <= 0 {
		p.IdleTimeout = 5 * time.Minute
	}
	if p.IdleInTransaction <= 0 {
		p.IdleInTransaction = 5 * time.Minute
	}
	if p.DefaultBudget <= 0 {
		p.DefaultBudget = defaultMaxConns
	}
	return p
}

var (
	errPoolBudget  = errors.New("database connection budget exhausted")
	errPinnedShare = errors.New("session-mode share exhausted")
	errPoolClosed  = errors.New("connection pool closed")
)

// poolKey names one credential's server connections. The replica is implicit:
// each broker process has its own pools.
// Every field that decides privileges is in the key: two entitlement tiers
// are different bindings with different roles, so they never share a server
// connection, and a binding whose role or target changes gets new ones.
type poolKey struct {
	pool     string // catalog pool name, or the actor when there is none
	binding  string // vault/service, the identity the cleanup journal uses
	mount    string
	role     string
	addr     string
	database string
}

// credential is one Vault-issued database login shared by a pool key's
// server connections. A retiring credential opens no new connections and is
// revoked once its last connection closes, or at its expiry.
type credential struct {
	lease    *Lease
	issued   time.Time
	rotateAt time.Time
	conns    int
	open     map[*serverConn]struct{} // every open connection on this login, idle or in use
	retiring bool
	revoked  bool
	margin   time.Duration // stop opening or reusing connections this long before expiry
}

// usable reports whether new work may still start on the credential.
func (c *credential) usable(now time.Time) bool {
	return now.Before(c.lease.ExpiresAt.Add(-c.margin))
}

// serverConn is one upstream connection, owned by at most one client at a time.
type serverConn struct {
	sess     *upstreamSession
	frontend *pgproto3.Frontend
	cred     *credential
	pool     *serverPool
	prepared map[string]bool   // broker-named prepared statements on this connection
	params   map[string]string // session parameters applied by the broker, as the client sent them
	actual   map[string]string // the same, as the server normalized them
	pinned   bool
	idleAt   time.Time
	// reported holds the server's last reported parameters as the broker left
	// them; seen holds reports made while a client held the connection. A
	// difference at check-in is session state the client left behind.
	reported map[string]string
	seen     map[string]string
}

type serverPool struct {
	key     poolKey
	svc     DatabaseService
	vault   string
	cur     *credential
	minting bool          // a background rotation is in flight
	mintMu  sync.Mutex    // one mint at a time per key
	creds   []*credential // every live credential, current included
	idle    []*serverConn
	pinned  int
	// parameters are the server's startup statuses, replayed to clients.
	parameters []pgproto3.ParameterStatus
}

// budget bounds server connections to one upstream address on this replica.
type budget struct {
	base    int // the whole fleet's budget for the database
	limit   int // this replica's share
	open    int
	waiters int
	changed chan struct{}
}

type serverPools struct {
	opts   PoolOptions
	broker *Broker
	logger *slog.Logger

	mu       sync.Mutex
	pools    map[poolKey]*serverPool
	budgets  map[string]*budget
	learning map[poolKey]*sync.Mutex // one parameter discovery per key
	closed   bool
	stop     chan struct{}
	done     chan struct{}
}

func newServerPools(b *Broker, opts PoolOptions) *serverPools {
	p := &serverPools{opts: opts.withDefaults(), broker: b, logger: b.logger, pools: map[poolKey]*serverPool{},
		budgets: map[string]*budget{}, learning: map[poolKey]*sync.Mutex{}, stop: make(chan struct{}), done: make(chan struct{})}
	go p.maintain()
	return p
}

func (p *serverPools) budgetFor(svc *DatabaseService) *budget {
	// The catalog's maxConns is the database's whole Gatehouse budget. In
	// pooled mode MaxConns caps client sessions instead, so an unset budget
	// falls back to the conservative default, not to that cap.
	limit := svc.MaxConns
	if limit <= 0 {
		limit = p.opts.DefaultBudget
	}
	bud, ok := p.budgets[svc.Addr]
	if !ok {
		bud = &budget{changed: make(chan struct{})}
		p.budgets[svc.Addr] = bud
	}
	bud.base = limit // budgets follow the live catalog
	bud.limit = max(1, limit/p.replicas())
	return bud
}

func (p *serverPools) replicas() int {
	if p.opts.LiveReplicas != nil {
		if n := p.opts.LiveReplicas(); n > 0 {
			return n
		}
	}
	return p.opts.Replicas
}

// trimLocked follows a change in fleet size: a smaller share closes idle
// connections down to it; a larger one wakes waiters.
func (p *serverPools) trimLocked() {
	replicas := p.replicas()
	for addr, bud := range p.budgets {
		limit := max(1, bud.base/replicas)
		if limit == bud.limit {
			continue
		}
		grew := limit > bud.limit
		bud.limit = limit
		for _, pool := range p.pools {
			if bud.open <= bud.limit {
				break
			}
			if pool.svc.Addr != addr {
				continue
			}
			for len(pool.idle) > 0 && bud.open > bud.limit {
				conn := pool.idle[len(pool.idle)-1]
				pool.idle = pool.idle[:len(pool.idle)-1]
				p.closeLocked(conn)
			}
		}
		if grew {
			bud.notify()
		}
	}
}

func (bud *budget) notify() {
	close(bud.changed)
	bud.changed = make(chan struct{})
}

// acquire returns a server connection for key, reusing an idle one, opening a
// new one within the database's budget, or waiting in a bounded queue. A
// pinned checkout also counts against the key's session-mode share.
func (p *serverPools) acquire(ctx context.Context, key poolKey, vaultID string, svc *DatabaseService, pinned bool) (*serverConn, error) {
	deadline := time.Now().Add(p.opts.QueueWait)
	waiting := false
	p.mu.Lock()
	defer func() {
		if waiting {
			p.budgets[svc.Addr].waiters--
		}
		p.mu.Unlock()
	}()
	for {
		if p.closed {
			return nil, errPoolClosed
		}
		pool := p.pools[key]
		if pool == nil {
			pool = &serverPool{key: key, svc: *svc, vault: vaultID}
			p.pools[key] = pool
		}
		pool.svc = *svc
		bud := p.budgetFor(svc)
		share := max(1, int(math.Floor(float64(bud.limit)*p.opts.SessionShare)))
		if pinned && pool.pinned >= share {
			return nil, errPinnedShare
		}
		// Reuse an idle connection on a current credential.
		for len(pool.idle) > 0 {
			conn := pool.idle[len(pool.idle)-1]
			pool.idle = pool.idle[:len(pool.idle)-1]
			if conn.cred.retiring {
				p.closeLocked(conn)
				continue
			}
			conn.pinned = pinned
			if pinned {
				pool.pinned++
			}
			return conn, nil
		}
		// Open a new one within budget, evicting another key's idle
		// connection on the same database if that is the only room.
		if bud.open >= bud.limit {
			p.evictIdleLocked(svc.Addr, key)
		}
		if bud.open < bud.limit {
			bud.open++
			p.mu.Unlock()
			conn, err := p.open(ctx, pool, *svc)
			p.mu.Lock()
			if err != nil {
				bud.open--
				bud.notify()
				return nil, err
			}
			conn.pinned = pinned
			if pinned {
				pool.pinned++
			}
			return conn, nil
		}
		if !waiting {
			if bud.waiters >= bud.limit*p.opts.QueueFactor {
				return nil, errPoolBudget
			}
			bud.waiters++
			waiting = true
		}
		changed := bud.changed
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errPoolBudget
		}
		p.mu.Unlock()
		timer := time.NewTimer(remaining)
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
		p.mu.Lock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

func (p *serverPools) evictIdleLocked(addr string, except poolKey) {
	for key, pool := range p.pools {
		if key == except || pool.svc.Addr != addr || len(pool.idle) == 0 {
			continue
		}
		conn := pool.idle[0]
		pool.idle = pool.idle[1:]
		p.closeLocked(conn)
		return
	}
}

// open dials one server connection with the key's current credential,
// minting the first credential if there is none yet.
func (p *serverPools) open(ctx context.Context, pool *serverPool, svc DatabaseService) (*serverConn, error) {
	cred, err := p.credentialFor(ctx, pool, svc)
	if err != nil {
		return nil, err
	}
	connectCtx, cancel := context.WithTimeout(ctx, p.broker.opts.HandshakeTimeout)
	defer cancel()
	server := map[string]string{"idle_in_transaction_session_timeout": strconv.FormatInt(p.opts.IdleInTransaction.Milliseconds(), 10)}
	sess, err := connectUpstreamWith(connectCtx, p.broker.opts.Dialer, &svc, cred.lease, nil, server)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		cred.conns--
		p.retireIfDrainedLocked(pool, cred)
		return nil, fmt.Errorf("connect upstream: %w", err)
	}
	frontend := pgproto3.NewFrontend(sess.conn, sess.conn)
	reported := map[string]string{}
	for _, p := range sess.parameters {
		reported[p.Name] = p.Value
	}
	conn := &serverConn{sess: sess, frontend: frontend, cred: cred, pool: pool, prepared: map[string]bool{}, params: map[string]string{},
		actual: map[string]string{}, reported: reported, seen: map[string]string{}}
	if cred.open == nil {
		cred.open = map[*serverConn]struct{}{}
	}
	cred.open[conn] = struct{}{}
	return conn, nil
}

// credentialFor reserves a connection on the key's current credential,
// minting one when the key has none or its only one has expired.
func (p *serverPools) credentialFor(ctx context.Context, pool *serverPool, svc DatabaseService) (*credential, error) {
	usable := func() *credential {
		p.mu.Lock()
		defer p.mu.Unlock()
		cur := pool.cur
		if cur != nil && !cur.retiring && !cur.revoked && cur.usable(time.Now()) {
			cur.conns++
			return cur
		}
		return nil
	}
	if cred := usable(); cred != nil {
		return cred, nil
	}
	pool.mintMu.Lock()
	defer pool.mintMu.Unlock()
	if cred := usable(); cred != nil {
		return cred, nil // another checkout minted while this one waited
	}
	if _, err := p.mintLocked(ctx, pool, svc); err != nil {
		return nil, err
	}
	if cred := usable(); cred != nil {
		return cred, nil
	}
	return nil, errors.New("pooled credential unavailable")
}

// mint issues a new credential for the key and makes it current. The previous
// one retires: it opens nothing more and is revoked when its last connection
// closes, so a rotation never cuts a running transaction.
// mintLocked requires pool.mintMu.
func (p *serverPools) mintLocked(ctx context.Context, pool *serverPool, svc DatabaseService) (*credential, error) {
	// A pooled credential serves the whole pool, so its cleanup record names
	// the pool, not any one agent or Pod.
	lease, err := p.broker.opts.Leases.Mint(ctx, AgentScope{VaultID: pool.vault, ActorID: "pool:" + pool.key.pool}, &svc)
	if err != nil {
		return nil, fmt.Errorf("mint pooled credential: %w", err)
	}
	if lease == nil || lease.ID == "" || lease.Username == "" || lease.Password == "" || !lease.ExpiresAt.After(time.Now().Add(time.Second)) {
		if lease != nil && lease.ID != "" {
			p.revoke(lease)
		}
		return nil, errors.New("invalid pooled database lease")
	}
	now := time.Now()
	life := lease.ExpiresAt.Sub(now)
	var jitter [2]byte
	_, _ = rand.Read(jitter[:])
	spread := time.Duration(float64(life) * 0.1 * float64(binary.BigEndian.Uint16(jitter[:])) / 65535)
	cred := &credential{lease: lease, issued: now, rotateAt: now.Add(time.Duration(float64(life)*p.opts.RotateFraction) - spread),
		margin: min(5*time.Second, life/4)}
	p.mu.Lock()
	defer p.mu.Unlock()
	if old := pool.cur; old != nil {
		old.retiring = true
		kept := pool.idle[:0]
		for _, conn := range pool.idle {
			if conn.cred == old {
				p.closeLocked(conn)
				continue
			}
			kept = append(kept, conn)
		}
		pool.idle = kept
		p.retireIfDrainedLocked(pool, old)
	}
	pool.cur = cred
	pool.creds = append(pool.creds, cred)
	return cred, nil
}

// release returns a connection after its client's transaction ended, or
// closes it when it cannot be reused safely.
func (p *serverPools) release(conn *serverConn, reusable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pool := conn.pool
	if conn.pinned {
		conn.pinned = false
		pool.pinned--
	}
	bud := p.budgets[pool.svc.Addr]
	// Over this replica's share after the fleet grew: give the connection back.
	over := bud != nil && bud.open > bud.limit
	if !reusable || over || p.closed || conn.cred.retiring || conn.cred.revoked || !conn.cred.usable(time.Now()) {
		p.closeLocked(conn)
		return
	}
	conn.idleAt = time.Now()
	pool.idle = append(pool.idle, conn)
	if bud != nil {
		bud.notify()
	}
}

func (p *serverPools) closeLocked(conn *serverConn) {
	_ = conn.sess.conn.Close()
	delete(conn.cred.open, conn)
	conn.cred.conns--
	if bud := p.budgets[conn.pool.svc.Addr]; bud != nil {
		bud.open--
		bud.notify()
	}
	p.retireIfDrainedLocked(conn.pool, conn.cred)
}

// retire stops a credential's use at once: it opens and reuses no more
// connections and is revoked when its last one closes. Used when a client
// changed the login itself, such as its role-level defaults.
func (p *serverPools) retire(cred *credential) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pool := range p.pools {
		if pool.cur == cred {
			pool.cur = nil
		}
	}
	cred.retiring = true
}

func (p *serverPools) retireIfDrainedLocked(pool *serverPool, cred *credential) {
	if !cred.retiring || cred.revoked || cred.conns > 0 {
		return
	}
	cred.revoked = true
	kept := pool.creds[:0]
	for _, c := range pool.creds {
		if c != cred {
			kept = append(kept, c)
		}
	}
	pool.creds = kept
	go p.revoke(cred.lease)
}

func (p *serverPools) revoke(lease *Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
	defer cancel()
	if err := p.broker.opts.Leases.Revoke(ctx, lease.ID); err != nil {
		p.logger.Warn("pgproxy: pooled credential revoke failed", slog.String("error", err.Error()))
	}
}

// maintain rotates credentials ahead of expiry, forces out credentials that
// reached expiry with connections still open, and closes idle connections.
func (p *serverPools) maintain() {
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		now := time.Now()
		var rotate []*serverPool
		p.mu.Lock()
		p.trimLocked()
		for _, pool := range p.pools {
			kept := pool.idle[:0]
			for _, conn := range pool.idle {
				if now.Sub(conn.idleAt) > p.opts.IdleTimeout {
					p.closeLocked(conn)
					continue
				}
				kept = append(kept, conn)
			}
			pool.idle = kept
			if cur := pool.cur; cur != nil && !pool.minting && !now.Before(cur.rotateAt) && (cur.conns > 0 || len(pool.idle) > 0) {
				pool.minting = true
				rotate = append(rotate, pool)
			}
			if cur := pool.cur; cur != nil && cur.conns == 0 && !now.Before(cur.rotateAt) {
				// Nothing uses it: retire now rather than renew an idle login.
				cur.retiring = true
				pool.cur = nil
				p.retireIfDrainedLocked(pool, cur)
			}
			live := pool.creds[:0]
			for _, cred := range pool.creds {
				if cred.revoked {
					continue
				}
				live = append(live, cred)
				if !now.Before(cred.lease.ExpiresAt) {
					// Expired with connections open: close them here, rather
					// than trust the Vault role's revocation to end them, and
					// revoke. A session on one loses its server and ends.
					cred.retiring, cred.revoked = true, true
					if pool.cur == cred {
						pool.cur = nil
					}
					for conn := range cred.open {
						_ = conn.sess.conn.Close()
					}
					go p.revoke(cred.lease)
				}
			}
			pool.creds = live
		}
		p.mu.Unlock()
		for _, pool := range rotate {
			go func(pool *serverPool) {
				ctx, cancel := context.WithTimeout(context.Background(), p.broker.opts.HandshakeTimeout)
				defer cancel()
				p.mu.Lock()
				svc := pool.svc
				p.mu.Unlock()
				pool.mintMu.Lock()
				_, err := p.mintLocked(ctx, pool, svc)
				pool.mintMu.Unlock()
				if err != nil {
					p.logger.Warn("pgproxy: pooled credential rotation failed; retrying", slog.String("error", err.Error()))
				}
				p.mu.Lock()
				pool.minting = false
				p.mu.Unlock()
			}(pool)
		}
	}
}

// close ends every idle connection and revokes every credential. Connections
// still owned by sessions close when those sessions end.
func (p *serverPools) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.stop)
	for _, pool := range p.pools {
		for _, conn := range pool.idle {
			p.closeLocked(conn)
		}
		pool.idle = nil
		for _, cred := range pool.creds {
			cred.retiring = true
			p.retireIfDrainedLocked(pool, cred)
		}
		pool.cur = nil
	}
	p.mu.Unlock()
	<-p.done
}

// stats reports open server connections per upstream, for tests and status.
//
//nolint:unused // used by the realpg tests
func (p *serverPools) stats(addr string) (open, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if bud := p.budgets[addr]; bud != nil {
		open = bud.open
	}
	for _, pool := range p.pools {
		if pool.svc.Addr == addr {
			idle += len(pool.idle)
		}
	}
	return open, idle
}

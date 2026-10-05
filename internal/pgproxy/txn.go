package pgproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

// sessionParams are the startup parameters a pooled session may set. The
// broker applies each client's values to whichever server connection it is
// given, so they never leak from one client to the next.
var sessionParams = []string{"DateStyle", "TimeZone", "client_encoding", "extra_float_digits", "search_path", "standard_conforming_strings", "statement_timeout"}

var errRebind = errors.New("server connection released; bind again")

// pooledSession is one client session multiplexed onto shared server
// connections. A server connection is bound at the client's first message
// and returned when the server reports the transaction idle and nothing the
// client sent is still unanswered. Session state pins the connection to the
// client for the rest of the session instead.
type pooledSession struct {
	b       *Broker
	key     poolKey
	vaultID string
	svc     DatabaseService
	client  net.Conn
	backend *pgproto3.Backend
	params  map[string]string
	event   auditchain.Event
	cancel  *cancelTarget

	writeMu sync.Mutex // every write to the client

	mu         sync.Mutex
	conn       *serverConn
	serverDone chan struct{}
	pinned     bool
	pending    int  // Query, Sync and FunctionCall not yet answered by ReadyForQuery
	unsynced   bool // extended-protocol messages sent since the last Sync
	executed   bool // an Execute sent since the last Sync
	txStatus   byte
	statements map[string]clientStatement
	swallow    []swallowEntry
	sendSeq    int
	recvSeq    int
	txnStart   time.Time
	txnFailed  bool
	killed     bool
	started    bool // a statement other than a safe encoding SET has run
	dataRows   int
	draining   bool // Shutdown asked the session to end at its next idle point
	flushedSeq int  // ReadyForQuery messages written to the client
	// statementBytes is the query text held in statements, which with the
	// statement count is capped so one session cannot exhaust broker memory.
	statementBytes int
}

const (
	maxSessionStatements     = 1000
	maxSessionStatementBytes = 16 << 20
)

// clientWriteTimeout ends a session whose client stops reading, so a full
// socket cannot hold a server connection. A variable only so tests can
// shorten it.
var clientWriteTimeout = 30 * time.Second

var (
	errRoleChange      = errors.New("role change on a pooled connection")
	errStatementLimit  = errors.New("prepared statement limit reached")
	errReadOnly        = errors.New("statement not allowed on a read-only login")
	errLexerChange     = errors.New("encoding change on a pooled connection")
	errPipelinedEscape = errors.New("backslash statement after an unsynced Execute")
)

// readOnlyMessage is the refusal a read-only login gets for a statement
// outside its allowlist, on either path.
const readOnlyMessage = "Agent Vault: this database login is read-only; only reads, transaction control and a few settings " +
	"(such as search_path and statement_timeout) are allowed, and temporary tables are refused"

// lexerChangeMessage is the refusal for a change to how the server reads
// later text.
const lexerChangeMessage = "Agent Vault: changing standard_conforming_strings or client_encoding is refused; " +
	"only on and UTF8, before any other statement, are allowed"

type clientStatement struct {
	query  string
	types  []uint32
	server string
}

type swallowEntry struct {
	close bool // CloseComplete, else ParseComplete
	seq   int
}

// serverStatementName names a prepared statement on server connections by its
// content, so clients that reuse names for different queries cannot collide.
func serverStatementName(query string, types []uint32) string {
	h := sha256.New()
	h.Write([]byte(query))
	for _, t := range types {
		h.Write(binary.BigEndian.AppendUint32(nil, t))
	}
	return "gatehouse_" + hex.EncodeToString(h.Sum(nil))[:24]
}

// servePooled runs a client session on the shared pool. It returns when the
// client leaves, the session is terminated, or the pool fails it.
func (b *Broker) servePooled(ctx context.Context, conn net.Conn, backend *pgproto3.Backend, scope AgentScope, svc *DatabaseService, token, hint, requested string, peer netip.Addr,
	startupParams map[string]string, event auditchain.Event) {
	key := poolKey{pool: scope.Pool, binding: databaseBinding(scope.VaultID, svc), mount: svc.Mount, role: svc.Role, addr: svc.Addr, database: svc.Database}
	if key.pool == "" {
		key.pool = "actor:" + scope.ActorID
	}
	s := &pooledSession{b: b, key: key, vaultID: scope.VaultID, svc: *svc, client: conn, backend: backend, event: event,
		params: map[string]string{}, txStatus: 'I', statements: map[string]clientStatement{}}
	wanted := map[string]bool{}
	for _, name := range sessionParams {
		wanted[name] = true
	}
	for key, value := range startupParams {
		if name, v, valid := brokercore.StartupParameter(key, value); valid && wanted[name] {
			s.params[name] = v
		}
	}
	if !b.trackPooled(conn, s) {
		writeClientError(backend, "57P01", "restarting", restartingMessage)
		return
	}
	defer b.untrackPooled(conn)
	unregister, clientKey, err := b.registerPooledCancel(s)
	if err != nil {
		writeClientError(backend, "08006", "upstream", "Agent Vault: could not start the session")
		return
	}
	defer unregister()
	parameters, err := b.pools.parameters(ctx, key, scope.VaultID, svc)
	if err != nil {
		b.logger.Warn("pgproxy: pooled session could not start", slog.String("service", svc.Name), slog.String("error", err.Error()))
		code, message, outcome := poolRefusal(err)
		b.auditDenied(event, outcome)
		writeClientError(backend, code, outcome, message)
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	for _, p := range parameters {
		value := p.Value
		switch {
		case p.Name == "application_name":
			value = startupParams["application_name"]
		case s.params[p.Name] != "":
			value = s.params[p.Name]
		}
		backend.Send(&pgproto3.ParameterStatus{Name: p.Name, Value: value})
	}
	backend.Send(clientKey)
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	backend.SetMaxBodyLen(64 << 20)

	opened := event
	opened.Event, opened.Outcome = auditchain.EventSessionOpen, "admitted"
	if err := b.auditRecord(opened); err != nil {
		return
	}
	defer func() {
		closed := event
		closed.Event, closed.Outcome = auditchain.EventSessionClose, "closed"
		_ = b.auditRecord(closed)
	}()
	b.logger.Info("pgproxy: pooled session established", slog.String("vault", scope.VaultID), slog.String("actor", scope.ActorID),
		slog.String("workload", scope.WorkloadID), slog.String("service", svc.Name))

	relayCtx, relayCancel := context.WithCancel(WithSession(b.ctx, Session(ctx)))
	defer relayCancel()
	authorizationDone := make(chan struct{})
	go func() {
		defer close(authorizationDone)
		b.authorizationLoop(relayCtx, token, hint, requested, scope, *svc, func() { s.killWith(&noticeAuthorization) }, peer)
	}()
	defer func() { relayCancel(); <-authorizationDone }()
	if !scope.NotAfter.IsZero() {
		// A pool Pod's session ends at its deadline, as on the unpooled path.
		deadline := time.AfterFunc(time.Until(scope.NotAfter), func() { s.killWith(&noticeDeadline) })
		defer deadline.Stop()
	}
	defer s.end()
	s.run(relayCtx)
}

// poolRefusal maps a pool error to the client's SQLSTATE and message, and to
// the audit outcome that alerting counts: a saturated budget is a degraded mode.
func poolRefusal(err error) (code, message, outcome string) {
	switch {
	case errors.Is(err, errPoolBudget):
		return "53300", "Agent Vault: database connection budget exhausted; retry shortly", "pool_budget"
	case errors.Is(err, errPinnedShare):
		return "53300", "Agent Vault: no session-mode connection available for session state (SET, temp tables, LISTEN, advisory locks)", "pinned_share"
	case errors.Is(err, errRoleChange):
		return "42501", "Agent Vault: ALTER ROLE, ALTER USER and ALTER DATABASE are refused on a pooled connection", "role_change"
	case errors.Is(err, errReadOnly):
		return "25006", readOnlyMessage, "read_only"
	case errors.Is(err, errLexerChange):
		return "42501", lexerChangeMessage, "encoding_change"
	case errors.Is(err, errPipelinedEscape):
		return "0A000", "Agent Vault: a statement containing a backslash cannot follow an Execute in the same batch on a pooled connection; send Sync first", "pipelined_escape"
	case errors.Is(err, errStatementLimit):
		return "54000", "Agent Vault: this session holds too many prepared statements; deallocate some", "statement_limit"
	default:
		return "08006", "Agent Vault: could not reach the database", "upstream"
	}
}

func (s *pooledSession) run(ctx context.Context) {
	errorUntilSync := false
	for {
		msg, err := s.backend.Receive()
		if err != nil {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				return
			}
			// Only a drain wakes a session's read. At an idle point the session
			// ends; otherwise it keeps serving until the next one.
			s.mu.Lock()
			if !s.draining {
				s.mu.Unlock()
				return
			}
			if s.idleLocked() {
				s.mu.Unlock()
				s.restart()
				return
			}
			_ = s.client.SetReadDeadline(time.Time{})
			s.mu.Unlock()
			continue
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			return
		}
		// A statement arriving at an idle point during a drain is not run.
		s.mu.Lock()
		stop := s.draining && s.idleLocked()
		s.mu.Unlock()
		if stop {
			s.restart()
			return
		}
		if errorUntilSync {
			if _, ok := msg.(*pgproto3.Sync); ok {
				errorUntilSync = false
				s.writeClient(&pgproto3.ReadyForQuery{TxStatus: s.status()})
			}
			continue
		}
		var sql string
		switch m := msg.(type) {
		case *pgproto3.Query:
			sql = m.String
		case *pgproto3.Parse:
			sql = m.Query
		}
		if refused := s.refuse(msg, sql); refused != nil {
			err = &refusalError{refused}
		} else if err = s.settleBeforeEscapes(ctx, sql); err != nil {
			// refused mid-batch, or the session ended while waiting
		} else {
			pin := sql != "" && needsSession(sql)
			for {
				if err = s.bind(ctx, pin); err == nil {
					err = s.forward(msg)
				}
				if !errors.Is(err, errRebind) {
					break
				}
			}
		}
		if err == nil {
			continue
		}
		var refusal *refusalError
		if !errors.As(err, &refusal) {
			return // server connection lost or client gone
		}
		code, message, outcome := poolRefusal(refusal.err)
		s.b.auditDenied(s.event, outcome)
		switch msg.(type) {
		case *pgproto3.Query, *pgproto3.FunctionCall: // each answered by its own ReadyForQuery
			s.writeClient(brokerError("ERROR", code, outcome, message), &pgproto3.ReadyForQuery{TxStatus: s.status()})
			continue
		}
		s.mu.Lock()
		midBatch := s.conn != nil && s.unsynced
		s.mu.Unlock()
		if midBatch {
			// Earlier messages of this batch already reached the server; an
			// error injected here would arrive out of order. End the session.
			s.writeClient(brokerError("FATAL", code, outcome, message))
			return
		}
		s.writeClient(brokerError("ERROR", code, outcome, message))
		errorUntilSync = true
	}
}

// refuse reports a statement the session must not send at all: a change to
// the shared login, a temporary object on a read-only login, or a prepared
// statement beyond the session's cap.
func (s *pooledSession) refuse(msg pgproto3.FrontendMessage, sql string) error {
	if sql != "" && changesRole(sql) {
		return errRoleChange
	}
	started := s.started
	if sql != "" {
		var refused bool
		if refused, started = changesLexer(sql, s.started); refused {
			return errLexerChange
		}
	}
	if s.svc.ReadOnly {
		// A fast-path FunctionCall names its function by OID, so it could
		// call set_config unseen.
		if _, call := msg.(*pgproto3.FunctionCall); call || sql != "" && !readOnlyAllowed(sql) {
			return errReadOnly
		}
	}
	if parse, ok := msg.(*pgproto3.Parse); ok && parse.Name != "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		old, replaces := s.statements[parse.Name]
		count, bytes := len(s.statements), s.statementBytes+len(parse.Query)
		if replaces {
			count--
			bytes -= len(old.query)
		}
		if count >= maxSessionStatements || bytes > maxSessionStatementBytes {
			return errStatementLimit
		}
	}
	s.started = started
	return nil
}

// settleBeforeEscapes holds a statement whose text contains a backslash until
// the server has answered everything sent before it. Only a backslash reads
// differently when an earlier statement turned standard_conforming_strings off
// or chose a client-only encoding, perhaps through a function the classifier
// cannot see. The broker learns of that change from the server's
// ParameterStatus, which ends the session, so waiting for the answers means a
// pipelined statement is never lexed under a setting the broker has not seen.
// After an Execute inside an unsynced batch there is no answer to wait for,
// so the statement is refused.
func (s *pooledSession) settleBeforeEscapes(ctx context.Context, sql string) error {
	if !strings.ContainsRune(sql, '\\') {
		return nil
	}
	for {
		s.mu.Lock()
		killed, bound, pending, executed := s.killed, s.conn != nil, s.pending, s.executed
		s.mu.Unlock()
		switch {
		case killed:
			return errors.New("session terminated")
		case bound && executed:
			return &refusalError{errPipelinedEscape}
		case !bound || pending == 0:
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

type refusalError struct{ err error }

func (e *refusalError) Error() string { return e.err.Error() }

func (s *pooledSession) status() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return 'I'
	}
	return s.txStatus
}

// bind makes sure the session holds a server connection, pinning it when the
// next statement needs session state.
func (s *pooledSession) bind(ctx context.Context, pin bool) error {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return errors.New("session terminated")
	}
	if s.conn != nil {
		if pin && !s.pinned {
			if err := s.b.pools.pin(s.conn); err != nil {
				s.mu.Unlock()
				return &refusalError{err}
			}
			s.pinned = true
		}
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	var conn *serverConn
	for attempt := 0; ; attempt++ {
		var err error
		if conn, err = s.b.pools.acquire(ctx, s.key, s.vaultID, &s.svc, pin); err != nil {
			return &refusalError{err}
		}
		// A connection idle for a while may have been closed by the server
		// or the network; check it before handing it a client's statement.
		if conn.idleAt.IsZero() || time.Since(conn.idleAt) < 30*time.Second || ping(conn, s.b.opts.HandshakeTimeout) == nil {
			break
		}
		s.b.pools.release(conn, false)
		if attempt >= 2 {
			return &refusalError{errors.New("database connections are failing")}
		}
	}
	if err := s.syncParams(conn); err != nil {
		s.b.pools.release(conn, false)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.killed {
		s.b.pools.release(conn, false)
		return errors.New("session terminated")
	}
	s.conn, s.pinned, s.txStatus = conn, pin, 'I'
	s.pending, s.unsynced, s.executed, s.swallow = 0, false, false, nil
	s.serverDone = make(chan struct{})
	s.bindCancel(conn)
	go s.readServer(conn, s.serverDone)
	return nil
}

// syncParams gives a server connection this client's session parameters
// before any of its statements run. Responses are consumed here, so the
// client sees none of them.
func (s *pooledSession) syncParams(conn *serverConn) error {
	var set [][2]string
	var reset []string
	for _, name := range sessionParams {
		want, wanted := s.params[name]
		have, has := conn.params[name]
		switch {
		case wanted && (!has || have != want):
			set = append(set, [2]string{name, want})
		case !wanted && has:
			reset = append(reset, name)
		}
	}
	if len(set) == 0 && len(reset) == 0 {
		return nil
	}
	// One simple query applies every change: set_config keeps each value
	// exactly as a startup parameter would, and a dollar-quoted literal is
	// immune to standard_conforming_strings and to quotes in the value.
	var statements []string
	for _, name := range reset {
		statements = append(statements, "RESET "+name) // fixed names only, never client text
	}
	for _, kv := range set {
		statements = append(statements, "SELECT set_config('"+kv[0]+"', "+dollarQuote(kv[1])+", false)")
	}
	f := conn.frontend
	f.Send(&pgproto3.Query{String: strings.Join(statements, "; ")})
	if err := f.Flush(); err != nil {
		return err
	}
	_ = conn.sess.conn.SetReadDeadline(time.Now().Add(s.b.opts.HandshakeTimeout))
	defer func() { _ = conn.sess.conn.SetReadDeadline(time.Time{}) }()
	failed := false
	var normalized []string // set_config returns each value as the server stores it
	for done := false; !done; {
		msg, err := f.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			failed = true
		case *pgproto3.DataRow:
			if len(m.Values) == 1 {
				normalized = append(normalized, string(m.Values[0]))
			}
		case *pgproto3.ParameterStatus:
			conn.reported[m.Name] = m.Value // the broker's own change
		case *pgproto3.ReadyForQuery:
			done = true
		}
	}
	if failed {
		return &refusalError{fmt.Errorf("session parameters rejected by the database")}
	}
	if len(normalized) != len(set) {
		return &refusalError{fmt.Errorf("session parameters not confirmed by the database")}
	}
	for _, name := range reset {
		delete(conn.params, name)
		delete(conn.actual, name)
	}
	for i, kv := range set {
		conn.params[kv[0]] = kv[1]
		conn.actual[kv[0]] = normalized[i]
	}
	return nil
}

// dollarQuote returns value as a dollar-quoted SQL literal whose tag does not
// occur in the value.
func dollarQuote(value string) string {
	tag := "$gh$"
	// The closing tag must be the first occurrence of the tag after the
	// opening one, including where the value's end runs into it.
	for i := 0; strings.Index(value+tag, tag) != len(value); i++ {
		tag = "$gh" + strconv.Itoa(i) + "$"
	}
	return tag + value + tag
}

// forward sends one client message to the bound server connection,
// translating prepared-statement names and tracking what awaits an answer.
func (s *pooledSession) forward(msg pgproto3.FrontendMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn := s.conn
	if conn == nil {
		return errRebind
	}
	if s.txnStart.IsZero() {
		s.txnStart = time.Now()
	}
	f := conn.frontend
	switch m := msg.(type) {
	case *pgproto3.Query:
		s.pending++
		s.sendSeq++
		f.Send(m)
	case *pgproto3.Sync:
		s.pending++
		s.sendSeq++
		s.unsynced, s.executed = false, false
		f.Send(m)
	case *pgproto3.FunctionCall:
		s.pending++
		s.sendSeq++
		f.Send(m)
	case *pgproto3.Parse:
		s.unsynced = true
		if m.Name == "" {
			f.Send(m)
			break
		}
		server := serverStatementName(m.Query, m.ParameterOIDs)
		if old, ok := s.statements[m.Name]; ok {
			s.statementBytes -= len(old.query)
		}
		s.statementBytes += len(m.Query)
		s.statements[m.Name] = clientStatement{query: m.Query, types: append([]uint32(nil), m.ParameterOIDs...), server: server}
		// Close first: the statement may already exist on this connection
		// from another client. Closing a missing statement is not an error.
		f.Send(&pgproto3.Close{ObjectType: 'S', Name: server})
		s.swallow = append(s.swallow, swallowEntry{close: true, seq: s.sendSeq})
		f.Send(&pgproto3.Parse{Name: server, Query: m.Query, ParameterOIDs: m.ParameterOIDs})
		conn.prepared[server] = true
	case *pgproto3.Bind:
		s.unsynced = true
		rewritten := *m
		rewritten.PreparedStatement = s.serverStatement(conn, m.PreparedStatement)
		f.Send(&rewritten)
	case *pgproto3.Describe:
		s.unsynced = true
		if m.ObjectType == 'S' {
			f.Send(&pgproto3.Describe{ObjectType: 'S', Name: s.serverStatement(conn, m.Name)})
			break
		}
		f.Send(m)
	case *pgproto3.Close:
		s.unsynced = true
		if m.ObjectType == 'S' && m.Name != "" {
			// Other clients may share the server statement: forget the name
			// and answer with a Close the server completes as a no-op.
			if old, ok := s.statements[m.Name]; ok {
				s.statementBytes -= len(old.query)
			}
			delete(s.statements, m.Name)
			f.Send(&pgproto3.Close{ObjectType: 'S', Name: "gatehouse_closed"})
			break
		}
		f.Send(m)
	case *pgproto3.Execute:
		s.unsynced, s.executed = true, true
		f.Send(m)
	case *pgproto3.Flush:
		s.unsynced = true
		f.Send(m)
	default:
		f.Send(m) // CopyData, CopyDone, CopyFail
	}
	if err := f.Flush(); err != nil {
		return fmt.Errorf("server write: %w", err)
	}
	return nil
}

// serverStatement maps a client statement name to the server one, preparing
// it on this connection first when it was prepared on another. Unknown names
// pass through so the server reports them missing.
func (s *pooledSession) serverStatement(conn *serverConn, name string) string {
	if name == "" {
		return ""
	}
	st, ok := s.statements[name]
	if !ok {
		return name
	}
	if !conn.prepared[st.server] {
		conn.frontend.Send(&pgproto3.Close{ObjectType: 'S', Name: st.server})
		conn.frontend.Send(&pgproto3.Parse{Name: st.server, Query: st.query, ParameterOIDs: st.types})
		s.swallow = append(s.swallow, swallowEntry{close: true, seq: s.sendSeq}, swallowEntry{seq: s.sendSeq})
		conn.prepared[st.server] = true
	}
	return st.server
}

// readServer relays one bound connection's responses to the client until the
// connection is released, lost or the session ends.
func (s *pooledSession) readServer(conn *serverConn, done chan struct{}) {
	defer close(done)
	for {
		msg, err := conn.frontend.Receive()
		if err != nil {
			s.mu.Lock()
			stale := s.conn != conn
			s.mu.Unlock()
			if !stale {
				// The server connection failed under an active client: the pool
				// closes it at its credential's expiry, otherwise it was lost.
				notice := &noticeUpstream
				if conn.cred != nil && conn.cred.lease != nil && !time.Now().Before(conn.cred.lease.ExpiresAt.Add(-conn.cred.margin)) {
					notice = &noticeCredential
				}
				s.killWith(notice)
			}
			return
		}
		s.mu.Lock()
		if s.conn != conn {
			s.mu.Unlock()
			return
		}
		if len(s.swallow) > 0 && s.swallow[0].seq == s.recvSeq {
			_, isClose := msg.(*pgproto3.CloseComplete)
			_, isParse := msg.(*pgproto3.ParseComplete)
			if (s.swallow[0].close && isClose) || (!s.swallow[0].close && isParse) {
				s.swallow = s.swallow[1:]
				s.mu.Unlock()
				continue
			}
		}
		flush := true
		var release bool
		var txn *auditchain.Event
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			s.txnFailed = true
			// The server skips to the next Sync: drop this batch's pending
			// swallows, and re-prepare statements before their next use.
			kept := s.swallow[:0]
			for _, e := range s.swallow {
				if e.seq != s.recvSeq {
					kept = append(kept, e)
				}
			}
			s.swallow = kept
			clear(conn.prepared)
		case *pgproto3.ParameterStatus:
			conn.seen[m.Name] = m.Value
			if unsafeLexerParameter(m.Name, m.Value) {
				// The classifier missed a change, such as a function that
				// calls set_config. Nothing more this client sends can be
				// read safely, so the session ends before the next statement.
				s.mu.Unlock()
				s.b.auditDenied(s.event, "encoding_change")
				s.killWith(&noticeEncoding)
				return
			}
		case *pgproto3.DataRow:
			s.dataRows++
			flush = s.dataRows%64 == 0
		case *pgproto3.ReadyForQuery:
			s.pending--
			s.recvSeq++
			s.txStatus = m.TxStatus
			if m.TxStatus == 'I' && !s.txnStart.IsZero() {
				e := s.event
				e.Event, e.Outcome = auditchain.EventTransaction, "completed"
				if s.txnFailed {
					e.Outcome = "failed"
				}
				e.Duration = time.Since(s.txnStart).Milliseconds()
				txn = &e
				s.txnStart, s.txnFailed = time.Time{}, false
			}
			release = s.pending <= 0 && !s.unsynced && m.TxStatus == 'I' && !s.pinned
			if release {
				s.conn = nil
				s.unbindCancel()
			}
		}
		s.mu.Unlock()
		s.writeClientMessage(msg, flush)
		if _, ready := msg.(*pgproto3.ReadyForQuery); ready {
			// Wake a draining session's read only once the client has this
			// answer, so the session never ends between a result and its
			// ReadyForQuery.
			s.mu.Lock()
			s.flushedSeq++
			if s.draining && s.idleLocked() {
				_ = s.client.SetReadDeadline(time.Now())
			}
			s.mu.Unlock()
		}
		if txn != nil {
			_ = s.b.auditRecord(*txn)
		}
		if release {
			conn.frontend = pgproto3.NewFrontend(conn.sess.conn, conn.sess.conn)
			s.b.pools.release(conn, s.verifyClean(conn))
			return
		}
	}
}

func (s *pooledSession) writeClient(msgs ...pgproto3.BackendMessage) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for _, m := range msgs {
		s.backend.Send(m)
	}
	_ = s.client.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
	_ = s.backend.Flush()
}

func (s *pooledSession) writeClientMessage(msg pgproto3.BackendMessage, flush bool) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.backend.Send(msg)
	if flush {
		_ = s.client.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
		if err := s.backend.Flush(); err != nil {
			go s.kill()
		}
	}
}

// restartingMessage tells a client its session ended for a planned restart,
// outside any transaction, so it can reconnect at once.
const restartingMessage = "Agent Vault: restarting; reconnect"

// idleLocked reports an idle point: no transaction open, nothing unanswered,
// and every ReadyForQuery already written to the client. Caller holds s.mu.
func (s *pooledSession) idleLocked() bool {
	return s.pending <= 0 && !s.unsynced && s.flushedSeq == s.recvSeq && (s.conn == nil || s.pinned && s.txStatus == 'I')
}

// beginDrain marks the session to end at its next idle point, waking its read
// now if it is idle already.
func (s *pooledSession) beginDrain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draining = true
	if s.idleLocked() {
		_ = s.client.SetReadDeadline(time.Now())
	}
}

// restart ends an idle session for a planned restart with 57P01.
func (s *pooledSession) restart() {
	_ = s.client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	s.writeClient(brokerError("FATAL", "57P01", "restarting", restartingMessage))
}

// end returns or closes the session's server connection when the client
// leaves. A connection in a transaction or with unanswered messages is
// closed; a pinned one is reset with DISCARD ALL before it is reused.
func (s *pooledSession) end() {
	s.mu.Lock()
	conn, done := s.conn, s.serverDone
	reusable := conn != nil && !s.killed && s.pending == 0 && !s.unsynced && s.txStatus == 'I'
	pinned := s.pinned
	s.conn = nil
	s.unbindCancel()
	s.mu.Unlock()
	if conn == nil {
		return
	}
	// Stop the reader without closing the socket, then take a fresh decoder.
	_ = conn.sess.conn.SetReadDeadline(time.Now())
	<-done
	_ = conn.sess.conn.SetReadDeadline(time.Time{})
	conn.frontend = pgproto3.NewFrontend(conn.sess.conn, conn.sess.conn)
	switch {
	case reusable && pinned:
		reusable = discardAll(conn, s.b.opts.HandshakeTimeout) == nil
	case reusable:
		reusable = s.verifyClean(conn)
	}
	s.b.pools.release(conn, reusable)
}

// leakCheck finds session state on a connection that left transaction mode
// unnoticed: temporary tables, listened channels, session advisory locks,
// holdable cursors, SQL-level prepared statements, or settings changed for the
// session other than the startup parameters the broker applies itself. The
// broker's own protocol-level statements are not from_sql, so they pass.
// The parameters the broker applied must still hold exactly its values; any
// other setting changed for the session is a leak.
func leakCheck(conn *serverConn) string {
	names := make([]string, 0, len(conn.actual))
	var check strings.Builder
	// DISCARD SEQUENCES drops currval and lastval state, which no catalog
	// shows; it runs in the same round trip as the check. Role-level defaults
	// ('role') survive DISCARD ALL and reach every connection on the login. A
	// role switched with SET ROLE ('switched') would hand the next client
	// another role's access, so that connection is closed, never reset and
	// reused. Anything else ('state') is reset with DISCARD ALL.
	check.WriteString("DISCARD SEQUENCES; SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_db_role_setting" +
		" WHERE setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user)) THEN 'role'" +
		" WHEN current_user <> session_user THEN 'switched' WHEN" +
		" EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = pg_my_temp_schema())" +
		" OR EXISTS (SELECT 1 FROM pg_type WHERE typnamespace = pg_my_temp_schema())" +
		" OR EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = pg_my_temp_schema())" +
		" OR EXISTS (SELECT 1 FROM pg_operator WHERE oprnamespace = pg_my_temp_schema())" +
		" OR EXISTS (SELECT 1 FROM pg_listening_channels())" +
		" OR EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid())" +
		" OR EXISTS (SELECT 1 FROM pg_cursors WHERE is_holdable)" +
		" OR EXISTS (SELECT 1 FROM pg_prepared_statements WHERE from_sql)")
	for _, name := range sessionParams { // fixed names only, never client text
		value, ok := conn.actual[name]
		if !ok {
			continue
		}
		names = append(names, name)
		check.WriteString(" OR current_setting('" + name + "') IS DISTINCT FROM " + dollarQuote(value))
	}
	check.WriteString(" OR EXISTS (SELECT 1 FROM pg_settings WHERE source = 'session' AND name <> ALL ('{" + strings.Join(names, ",") + "}'::text[]))")
	check.WriteString(" THEN 'state' ELSE 'clean' END")
	return check.String()
}

// verifyClean is the backstop behind needsSession, run at every check-in
// after the client already has its answer: a connection with state the
// classifier missed is reset with DISCARD ALL before anyone else gets it, and
// the catch is audited. It reports whether the connection may be reused.
func (s *pooledSession) verifyClean(conn *serverConn) bool {
	// A reported parameter that ends the session differing from where the
	// broker left it was set for the session. SET LOCAL reverts at commit,
	// so its final report matches and is not a leak.
	leaked := false
	for name, value := range conn.seen {
		if conn.reported[name] != value {
			leaked = true
		}
	}
	clear(conn.seen)
	// The query runs even when a reported parameter already showed state:
	// DISCARD ALL would reset that parameter but neither role-level defaults
	// nor a switched role, so those are checked before any reuse.
	{
		state, err := queryValue(conn, leakCheck(conn), s.b.opts.HandshakeTimeout)
		if err != nil || state != "clean" && state != "state" && state != "role" && state != "switched" {
			return false
		}
		if state == "switched" {
			e := s.event
			e.Event, e.Outcome = auditchain.EventStateLeak, "role_switched"
			_ = s.b.auditRecord(e)
			s.b.logger.Warn("pgproxy: a switched role found at check-in; closing the connection", slog.String("service", s.svc.Name))
			return false
		}
		if state == "role" {
			// The login itself changed: no connection on it is safe to reuse.
			e := s.event
			e.Event, e.Outcome = auditchain.EventStateLeak, "role_defaults"
			_ = s.b.auditRecord(e)
			s.b.logger.Warn("pgproxy: role-level defaults found at check-in; retiring the credential", slog.String("service", s.svc.Name))
			s.b.pools.retire(conn.cred)
			return false
		}
		leaked = leaked || state == "state"
	}
	if !leaked {
		return true
	}
	e := s.event
	e.Event, e.Outcome = auditchain.EventStateLeak, "reset"
	_ = s.b.auditRecord(e)
	s.b.logger.Warn("pgproxy: session state found at check-in; resetting the connection", slog.String("service", s.svc.Name))
	return discardAll(conn, s.b.opts.HandshakeTimeout) == nil
}

// queryValue runs a query on an idle connection and returns the last row's
// single text value.
func queryValue(conn *serverConn, sql string, timeout time.Duration) (string, error) {
	conn.frontend.Send(&pgproto3.Query{String: sql})
	if err := conn.frontend.Flush(); err != nil {
		return "", err
	}
	_ = conn.sess.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.sess.conn.SetReadDeadline(time.Time{}) }()
	var value string
	failed := false
	for {
		msg, err := conn.frontend.Receive()
		if err != nil {
			return "", err
		}
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			if len(m.Values) == 1 {
				value = string(m.Values[0])
			}
		case *pgproto3.ErrorResponse:
			failed = true
		case *pgproto3.ReadyForQuery:
			if failed || m.TxStatus != 'I' {
				return "", errors.New("check query failed")
			}
			return value, nil
		}
	}
}

// ping round-trips an empty query, which the server answers without work.
func ping(conn *serverConn, timeout time.Duration) error {
	conn.frontend.Send(&pgproto3.Query{})
	if err := conn.frontend.Flush(); err != nil {
		return err
	}
	_ = conn.sess.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.sess.conn.SetReadDeadline(time.Time{}) }()
	for {
		msg, err := conn.frontend.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			return errors.New("server refused a ping")
		case *pgproto3.ReadyForQuery:
			if m.TxStatus != 'I' {
				return errors.New("idle connection not idle")
			}
			return nil
		}
	}
}

// discardAll resets every kind of session state on a connection.
func discardAll(conn *serverConn, timeout time.Duration) error {
	conn.frontend.Send(&pgproto3.Query{String: "DISCARD ALL"})
	if err := conn.frontend.Flush(); err != nil {
		return err
	}
	_ = conn.sess.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.sess.conn.SetReadDeadline(time.Time{}) }()
	failed := false
	for {
		msg, err := conn.frontend.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			failed = true
		case *pgproto3.ParameterStatus:
			conn.reported[m.Name] = m.Value
		case *pgproto3.ReadyForQuery:
			if failed || m.TxStatus != 'I' {
				return errors.New("DISCARD ALL failed")
			}
			clear(conn.seen)
			clear(conn.prepared)
			clear(conn.params)
			clear(conn.actual)
			return nil
		}
	}
}

// kill ends the session now: the client is disconnected, and a running
// statement on its server connection is cancelled and the connection closed.
// The connection is detached first, under the session lock, so it cannot
// have gone back to the pool and to another client when the cancel lands.
func (s *pooledSession) kill() { s.killWith(nil) }

// killWith is kill with a close notice for the client, written once the
// server connection is detached, so no later server message follows it. A
// restart that finds a transaction open says so instead. A client whose
// writes are blocked gets no notice rather than holding up the kill.
func (s *pooledSession) killWith(n *closeNotice) {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return
	}
	s.killed = true
	if n != nil && *n == noticeRestarting && !s.idleLocked() {
		n = &noticeRestartCut
	}
	conn := s.conn
	s.conn = nil
	if conn != nil {
		s.unbindCancel()
	}
	s.mu.Unlock()
	// Stop the running statement first, so a client that is slow to read the
	// notice cannot keep it running.
	if conn != nil {
		if conn.sess.backendKey != nil {
			ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
			s.b.cancelUpstream(ctx, conn.sess.conn.RemoteAddr().String(), &s.svc,
				&pgproto3.CancelRequest{ProcessID: conn.sess.backendKey.ProcessID, SecretKey: conn.sess.backendKey.SecretKey})
			cancel()
		}
		s.b.pools.release(conn, false)
	}
	if n != nil && s.writeMu.TryLock() {
		_ = s.client.SetWriteDeadline(time.Now().Add(noticeWriteTimeout))
		s.backend.Send(brokerError("FATAL", n.code, n.reason, n.message))
		_ = s.backend.Flush()
		s.writeMu.Unlock()
	}
	_ = s.client.Close()
}

// registerPooledCancel gives the client a cancel key that reaches whichever
// server connection the session holds when the cancel arrives.
func (b *Broker) registerPooledCancel(s *pooledSession) (func(), *pgproto3.BackendKeyData, error) {
	target := &cancelTarget{}
	s.cancel = target
	for {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, nil, err
		}
		pid, secret := binary.BigEndian.Uint32(random[:4]), random[4:]
		key := cancelKey(pid, secret)
		b.mu.Lock()
		if _, exists := b.cancellations[key]; exists {
			b.mu.Unlock()
			continue
		}
		b.cancellations[key] = target
		b.mu.Unlock()
		return func() {
			b.mu.Lock()
			delete(b.cancellations, key)
			b.mu.Unlock()
			target.mu.Lock()
			target.active = false
			target.mu.Unlock()
		}, &pgproto3.BackendKeyData{ProcessID: pid, SecretKey: append([]byte(nil), secret...)}, nil
	}
}

func (s *pooledSession) bindCancel(conn *serverConn) {
	if conn.sess.backendKey == nil {
		return
	}
	s.cancel.mu.Lock()
	s.cancel.active = true
	s.cancel.addr = conn.sess.conn.RemoteAddr().String()
	s.cancel.svc = s.svc
	s.cancel.key = pgproto3.CancelRequest{ProcessID: conn.sess.backendKey.ProcessID, SecretKey: append([]byte(nil), conn.sess.backendKey.SecretKey...)}
	s.cancel.mu.Unlock()
}

func (s *pooledSession) unbindCancel() {
	s.cancel.mu.Lock()
	s.cancel.active = false
	s.cancel.mu.Unlock()
}

// parameters returns the server's startup parameter statuses for a pool key,
// learning them from one server connection the first time.
func (p *serverPools) parameters(ctx context.Context, key poolKey, vaultID string, svc *DatabaseService) ([]pgproto3.ParameterStatus, error) {
	cached := func() []pgproto3.ParameterStatus {
		p.mu.Lock()
		defer p.mu.Unlock()
		if pool := p.pools[key]; pool != nil && len(pool.parameters) > 0 {
			return append([]pgproto3.ParameterStatus(nil), pool.parameters...)
		}
		return nil
	}
	if out := cached(); out != nil {
		return out, nil
	}
	// One connecting client learns them; the others wait for its answer.
	p.mu.Lock()
	learn, ok := p.learning[key]
	if !ok {
		learn = &sync.Mutex{}
		p.learning[key] = learn
	}
	p.mu.Unlock()
	learn.Lock()
	defer learn.Unlock()
	if out := cached(); out != nil {
		return out, nil
	}
	conn, err := p.acquire(ctx, key, vaultID, svc, false)
	if err != nil {
		return nil, err
	}
	params := append([]pgproto3.ParameterStatus(nil), conn.sess.parameters...)
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	p.mu.Lock()
	conn.pool.parameters = params
	p.mu.Unlock()
	p.release(conn, true)
	return params, nil
}

// pin moves an already bound connection into the key's session-mode share.
func (p *serverPools) pin(conn *serverConn) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	bud := p.budgets[conn.pool.svc.Addr]
	limit := 1
	if bud != nil {
		limit = bud.limit
	}
	if conn.pool.pinned >= max(1, int(float64(limit)*p.opts.SessionShare)) {
		return errPinnedShare
	}
	conn.pinned = true
	conn.pool.pinned++
	return nil
}

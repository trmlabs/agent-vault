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
)

// sessionParams are the startup parameters a pooled session may set. The
// broker applies each client's values to whichever server connection it is
// given, so they never leak from one client to the next.
var sessionParams = []string{"DateStyle", "TimeZone", "client_encoding", "extra_float_digits", "search_path", "standard_conforming_strings", "statement_timeout"}

// validSessionParam accepts the values drivers send by default. client_encoding
// is any encoding name (libpq sends the locale's, such as SQL_ASCII under the C
// locale); the server rejects a name it does not support. The rest use the
// same bounds as unpooled sessions.
func validSessionParam(name, value string) bool {
	if name != "client_encoding" {
		return validStartupValue(name, value)
	}
	if value == "" || len(value) > 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c >= 0x80 || c != '_' && c != '-' && !identChar(c) {
			return false
		}
	}
	return true
}

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
	txStatus   byte
	statements map[string]clientStatement
	swallow    []swallowEntry
	sendSeq    int
	recvSeq    int
	txnStart   time.Time
	txnFailed  bool
	killed     bool
	dataRows   int
}

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
	for _, name := range sessionParams {
		if value, ok := startupParams[name]; ok && validSessionParam(name, value) {
			s.params[name] = value
		}
	}
	unregister, clientKey, err := b.registerPooledCancel(s)
	if err != nil {
		writeClientError(backend, "08006", "Agent Vault: could not start the session")
		return
	}
	defer unregister()
	parameters, err := b.pools.parameters(ctx, key, scope.VaultID, svc)
	if err != nil {
		b.logger.Warn("pgproxy: pooled session could not start", slog.String("service", svc.Name), slog.String("error", err.Error()))
		code, message := poolRefusal(err)
		writeClientError(backend, code, message)
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

	relayCtx, relayCancel := context.WithCancel(b.ctx)
	defer relayCancel()
	authorizationDone := make(chan struct{})
	go func() {
		defer close(authorizationDone)
		b.authorizationLoop(relayCtx, token, hint, requested, scope, *svc, s.kill, peer)
	}()
	defer func() { relayCancel(); <-authorizationDone }()
	if !scope.NotAfter.IsZero() {
		// A pool Pod's session ends at its deadline, as on the unpooled path.
		deadline := time.AfterFunc(time.Until(scope.NotAfter), s.kill)
		defer deadline.Stop()
	}
	defer s.end()
	s.run(relayCtx)
}

func poolRefusal(err error) (string, string) {
	switch {
	case errors.Is(err, errPoolBudget):
		return "53300", "Agent Vault: database connection budget exhausted; retry shortly"
	case errors.Is(err, errPinnedShare):
		return "53300", "Agent Vault: no session-mode connection available for session state (SET, temp tables, LISTEN, advisory locks)"
	default:
		return "08006", "Agent Vault: could not reach the database"
	}
}

func (s *pooledSession) run(ctx context.Context) {
	errorUntilSync := false
	for {
		msg, err := s.backend.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
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
		pin := sql != "" && needsSession(sql)
		for {
			if err = s.bind(ctx, pin); err == nil {
				err = s.forward(msg)
			}
			if !errors.Is(err, errRebind) {
				break
			}
		}
		if err == nil {
			continue
		}
		var refusal *refusalError
		if !errors.As(err, &refusal) {
			return // server connection lost or client gone
		}
		code, message := poolRefusal(refusal.err)
		if _, simple := msg.(*pgproto3.Query); simple {
			s.writeClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: message}, &pgproto3.ReadyForQuery{TxStatus: s.status()})
			continue
		}
		s.mu.Lock()
		midBatch := s.conn != nil && s.unsynced
		s.mu.Unlock()
		if midBatch {
			// Earlier messages of this batch already reached the server; an
			// error injected here would arrive out of order. End the session.
			s.writeClient(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: message})
			return
		}
		s.writeClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: message})
		errorUntilSync = true
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
	s.pending, s.unsynced, s.swallow = 0, false, nil
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
		s.unsynced = false
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
			delete(s.statements, m.Name)
			f.Send(&pgproto3.Close{ObjectType: 'S', Name: "gatehouse_closed"})
			break
		}
		f.Send(m)
	case *pgproto3.Execute, *pgproto3.Flush:
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
				s.kill() // the server connection failed under an active client
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
	_ = s.backend.Flush()
}

func (s *pooledSession) writeClientMessage(msg pgproto3.BackendMessage, flush bool) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.backend.Send(msg)
	if flush {
		if err := s.backend.Flush(); err != nil {
			go s.kill()
		}
	}
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
// holdable cursors, or settings changed for the session other than the
// startup parameters the broker applies itself.
// The parameters the broker applied must still hold exactly its values; any
// other setting changed for the session is a leak.
func leakCheck(conn *serverConn) string {
	names := make([]string, 0, len(conn.actual))
	var check strings.Builder
	check.WriteString("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = pg_my_temp_schema())" +
		" OR EXISTS (SELECT 1 FROM pg_listening_channels())" +
		" OR EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid())" +
		" OR EXISTS (SELECT 1 FROM pg_cursors WHERE is_holdable)")
	for _, name := range sessionParams { // fixed names only, never client text
		value, ok := conn.actual[name]
		if !ok {
			continue
		}
		names = append(names, name)
		check.WriteString(" OR current_setting('" + name + "') IS DISTINCT FROM " + dollarQuote(value))
	}
	check.WriteString(" OR EXISTS (SELECT 1 FROM pg_settings WHERE source = 'session' AND name <> ALL ('{" + strings.Join(names, ",") + "}'::text[]))")
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
	if !leaked {
		dirty, err := queryBool(conn, leakCheck(conn), s.b.opts.HandshakeTimeout)
		if err != nil {
			return false
		}
		leaked = dirty
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

// queryBool runs a one-row, one-column boolean query on an idle connection.
func queryBool(conn *serverConn, sql string, timeout time.Duration) (bool, error) {
	conn.frontend.Send(&pgproto3.Query{String: sql})
	if err := conn.frontend.Flush(); err != nil {
		return false, err
	}
	_ = conn.sess.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.sess.conn.SetReadDeadline(time.Time{}) }()
	var value string
	failed := false
	for {
		msg, err := conn.frontend.Receive()
		if err != nil {
			return false, err
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
				return false, errors.New("check query failed")
			}
			return value == "t", nil
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
func (s *pooledSession) kill() {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return
	}
	s.killed = true
	conn := s.conn
	s.mu.Unlock()
	_ = s.client.Close()
	if conn != nil && conn.sess.backendKey != nil {
		ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		s.b.cancelUpstream(ctx, conn.sess.conn.RemoteAddr().String(), &s.svc,
			&pgproto3.CancelRequest{ProcessID: conn.sess.backendKey.ProcessID, SecretKey: conn.sess.backendKey.SecretKey})
		cancel()
	}
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

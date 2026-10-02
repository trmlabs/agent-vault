package taskrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const cancelCode = 80877102

type cancelTarget struct {
	mu      sync.Mutex
	active  bool
	address string
	packet  []byte
	expiry  time.Time
	binding string
}

// PostgreSQL uses outer TLS (the sandbox's public-CA stunnel can provide it).
// Only the fixed database/user and a public placeholder are accepted. The relay
// substitutes proof and replaces the broker cancellation key with a local one.
//
// Admission (the live Kubernetes check plus the durable "admitted" row) happens
// only after the peer, the TLS handshake, the startup message and the
// placeholder have all been validated. Before that point a connection costs no
// API request. The paired sandbox can make the relay write a "denied:<reason>"
// row by sending a rejected startup or placeholder; a peer that closes without
// sending a startup packet leaves nothing.
func (r *relay) postgres(conn net.Conn, binding PostgresConfig) {
	_ = conn.SetDeadline(minTime(r.config.Deadline, time.Now().Add(handshakeTimeout)))
	peer := conn.RemoteAddr().String()
	// The listener hands over the connection before the TLS handshake, so a
	// foreign address is refused before the relay reads a byte from it. Only
	// the first foreign address is journaled: an unauthenticated network
	// neighbour must not be able to drive one fsync per connect, and one row
	// is enough to show the network isolation the operator attested to failed.
	if !r.pair.peerMatches(peer) {
		if r.foreignPeer.CompareAndSwap(false, true) {
			_ = r.record("postgres", "denied:peer")
		}
		return
	}
	packet, e := readStartupPacket(conn)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("postgres", "denied:bad-startup")
		}
		return
	}
	if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
		r.cancelPostgres(peer, packet, binding)
		return
	}
	var startup pgproto3.StartupMessage
	c := &binding
	if startup.Decode(packet[4:]) != nil || startup.ProtocolVersion != pgproto3.ProtocolVersionNumber || !validStartup(startup.Parameters, c) {
		_ = r.record("postgres", "denied:bad-startup")
		_, _ = conn.Write(errorFrame("08004", "Gatehouse: connection refused: use this binding's database and user, and only the "+
			startupParameterList+" startup parameters, with bounded values (set others with SET after connecting)"))
		return
	}
	// Preserve validated client behavior while fixing connection authority to the
	// operator's database/user. Never forward arbitrary backend options.
	parameters := map[string]string{"user": c.User, "database": c.Database}
	for key, value := range startup.Parameters {
		if name, v, valid := brokercore.StartupParameter(key, value); valid {
			parameters[name] = v
		}
	}
	packet, e = (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
	if e != nil {
		return
	}
	backend := pgproto3.NewBackend(conn, conn)
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if backend.Flush() != nil {
		return
	}
	typ, password, e := readPGFrame(conn, 1024)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("postgres", "denied:bad-startup")
		}
		return
	}
	if typ != 'p' || string(password) != c.Placeholder+"\x00" {
		_ = r.record("postgres", "denied:placeholder")
		_, _ = conn.Write(errorFrame("28P01", "Gatehouse: wrong placeholder password for this binding"))
		return
	}
	// Everything the sandbox can influence has been validated. Admit: live pair
	// check, then the durable "admitted" row, before any proof is read or used.
	if r.admit(r.ctx, peer, "postgres") != nil {
		return
	}
	defer func() { _ = r.record("postgres", "terminal") }()
	// From here on the worker is always told why, in fixed words. Only a
	// withdrawn task (the pair check, or a relay that is stopping) closes
	// silently.
	tell := func(frame []byte) { _, _ = conn.Write(frame) }
	refused := func() { tell(errorFrame("08004", genericRefusalMessage)) }
	if !r.config.Deadline.After(time.Now()) {
		tell(errorFrame("08006", sessionEndedMessage))
		return
	}
	proof, expiry, e := readProof(c.Upstream, r.config.Deadline)
	if e != nil {
		tell(errorFrame("28000", notVerifiedMessage))
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	up, e := dialUpstream(r.ctx, c.Upstream)
	if e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(handshakeTimeout)))
	// The runner session rides the broker-side stream ahead of the startup
	// packet this sidecar authors; the worker's own bytes never carry it.
	if session := readSession(c.Upstream); session != "" {
		if _, e = io.WriteString(up, "GHSESS1 "+session+"\n"); e != nil {
			tell(errorFrame("08001", unreachableMessage))
			return
		}
	}
	if _, e = up.Write(packet); e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	typ, body, e := readPGFrame(up, 8192)
	if e == nil && typ == 'E' {
		tell(refusalFrame(body))
		return
	}
	if e != nil || typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != 3 {
		refused()
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	if !time.Now().Before(expiry) {
		tell(errorFrame("08006", sessionEndedMessage))
		return
	}
	authPacket, e := (&pgproto3.PasswordMessage{Password: proof}).Encode(nil)
	if e != nil {
		refused()
		return
	}
	if _, e = up.Write(authPacket); e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	// Accumulate the bounded startup response before disclosing anything. Broker
	// refusals are rewritten in fixed words; never relay their error text.
	var response []byte
	var remove func()
	defer func() {
		if remove != nil {
			remove()
		}
	}()
	authenticated := false
	for len(response) < 65536 {
		typ, body, e = readPGFrame(up, 8192)
		if e != nil {
			refused()
			return
		}
		switch typ {
		case 'R':
			if authenticated || len(body) != 4 || binary.BigEndian.Uint32(body) != 0 {
				refused()
				return
			}
			authenticated = true
		case 'S':
			if !authenticated {
				refused()
				return
			}
		case 'K':
			if !authenticated || len(body) != 8 || remove != nil {
				refused()
				return
			}
			var local []byte
			local, remove, e = r.registerCancel(body, up.RemoteAddr().String(), expiry, binding.Listen)
			if e != nil {
				refused()
				return
			}
			body = local
		case 'Z':
			if !authenticated || len(body) != 1 {
				refused()
				return
			}
		case 'E':
			tell(refusalFrame(body))
			return
		default:
			refused()
			return
		}
		response = append(response, encodePGFrame(typ, body)...)
		if typ == 'Z' {
			break
		}
	}
	if typ != 'Z' {
		refused()
		return
	}
	if r.pair.check(r.ctx, peer) != nil || r.record("postgres", "established") != nil {
		return
	}
	_ = conn.SetDeadline(expiry)
	_ = up.SetDeadline(expiry)
	if _, e = conn.Write(response); e != nil {
		return
	}
	copyPostgres(r.ctx, conn, up, expiry)
}

// validStartup fixes database and user to the binding and allows only the
// startup parameters brokercore.StartupValue accepts, the same rule the broker
// applies, so a client that passes here is never refused there.
func validStartup(parameters map[string]string, c *PostgresConfig) bool {
	if parameters["database"] != c.Database || parameters["user"] != c.User {
		return false
	}
	for key, value := range parameters {
		if key == "database" || key == "user" {
			continue
		}
		if _, _, ok := brokercore.StartupParameter(key, value); !ok {
			return false
		}
	}
	return true
}

// startupParameterList names the accepted parameters for the refusal message.
var startupParameterList = strings.Join(brokercore.StartupParameters[:len(brokercore.StartupParameters)-1], ", ") +
	" and " + brokercore.StartupParameters[len(brokercore.StartupParameters)-1]

func readStartupPacket(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, e := io.ReadFull(reader, length[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(length[:])
	if n < 8 || n > 8192 {
		return nil, errDenied
	}
	b := make([]byte, int(n))
	copy(b, length[:])
	_, e := io.ReadFull(reader, b[4:])
	return b, e
}
func readPGFrame(reader io.Reader, max uint32) (byte, []byte, error) {
	var header [5]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return 0, nil, e
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n < 4 || n > max {
		return 0, nil, errDenied
	}
	b := make([]byte, int(n)-4)
	_, e := io.ReadFull(reader, b)
	return header[0], b, e
}
func encodePGFrame(typ byte, body []byte) []byte {
	out := []byte{typ}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4))
	return append(out, body...)
}

func (r *relay) registerCancel(coreKey []byte, address string, expiry time.Time, binding string) ([]byte, func(), error) {
	r.cancelMu.Lock()
	defer r.cancelMu.Unlock()
	if r.cancellations == nil {
		r.cancellations = make(map[string]*cancelTarget)
	}
	for {
		local := make([]byte, 8)
		if _, e := rand.Read(local); e != nil {
			return nil, nil, errDenied
		}
		if _, exists := r.cancellations[string(local)]; exists {
			continue
		}
		packet := binary.BigEndian.AppendUint32(nil, 16)
		packet = binary.BigEndian.AppendUint32(packet, cancelCode)
		packet = append(packet, coreKey...)
		target := &cancelTarget{active: true, address: address, packet: packet, expiry: expiry, binding: binding}
		key := string(local)
		r.cancellations[key] = target
		return local, func() {
			r.cancelMu.Lock()
			delete(r.cancellations, key)
			r.cancelMu.Unlock()
			target.mu.Lock()
			target.active = false
			target.mu.Unlock()
		}, nil
	}
}

// cancelPostgres is reached without admission: a cancel carries no session to
// admit, only a key that must match an established one. It journals its own
// outcome so a rejected key is as visible as a rejected startup.
func (r *relay) cancelPostgres(peer string, packet []byte, binding PostgresConfig) {
	if len(packet) != 16 {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	r.cancelMu.Lock()
	target := r.cancellations[string(packet[8:])]
	r.cancelMu.Unlock()
	if target == nil || !target.mu.TryLock() {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	defer target.mu.Unlock()
	if target.binding != binding.Listen || !target.active || !time.Now().Before(target.expiry) || r.pair.check(r.ctx, peer) != nil {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	if r.record("postgres", "cancel") != nil {
		return
	}
	// Pin to the established broker socket, not a newly selected service replica.
	c := binding.Upstream
	c.Address = target.address
	ctx, cancel := context.WithDeadline(r.ctx, minTime(target.expiry, time.Now().Add(handshakeTimeout)))
	defer cancel()
	up, e := dialUpstream(ctx, c)
	if e != nil {
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = up.Close() })
	defer stop()
	if !time.Now().Before(target.expiry) || r.pair.check(ctx, peer) != nil {
		return
	}
	if _, e = up.Write(target.packet); e == nil {
		_, _ = io.Copy(io.Discard, up)
	}
}

// errorField returns one field of a PostgreSQL ErrorResponse body.
func errorField(body []byte, want byte) string {
	for len(body) > 0 && body[0] != 0 {
		field := body[0]
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			return ""
		}
		if field == want {
			return string(body[1 : 1+end])
		}
		body = body[2+end:]
	}
	return ""
}

// sqlState returns the SQLSTATE field of a PostgreSQL ErrorResponse body.
func sqlState(body []byte) string { return errorField(body, 'C') }

const (
	sessionEndedMessage   = "Gatehouse ended the session (deadline or revocation)"
	unreachableMessage    = "cannot reach Gatehouse"
	notVerifiedMessage    = "Gatehouse could not verify this worker"
	workerCapMessage      = "this worker reached its session cap"
	databaseBudgetMessage = "the database's Gatehouse connection budget is full; retry shortly"
	genericRefusalMessage = "Gatehouse: the broker refused this connection"
)

type refusal struct{ code, message string }

// refusalsByReason maps the broker's reason code (brokercore.RefusalReasonField)
// to the relay's fixed words. Broker message text is never forwarded.
var refusalsByReason = map[string]refusal{
	"actor_limit":    {"53300", workerCapMessage},
	"database_limit": {"53300", databaseBudgetMessage},
	"pool_budget":    {"53300", databaseBudgetMessage},
	"capacity":       {"53300", "Gatehouse is at capacity; retry shortly"},
	"pinned_share":   {"53300", "no session-mode database connection is free for session state (SET, temp tables, LISTEN, advisory locks); retry shortly"},
	"not_ready":      {"57P03", "Gatehouse is starting; retry in a few seconds"},
	"no_database":    {"3D000", "this database isn't in the Gatehouse catalog for your pool"},
	"authentication": {"28000", notVerifiedMessage},
	"upstream":       {"08006", "Gatehouse could not reach the database; retry"},
	"credential":     {"08006", "Gatehouse could not get a database credential; retry shortly"},
}

// refusalsByCode covers a broker refusal whose reason has no entry of its own:
// every authorization decision is a 42501, whatever its reason.
var refusalsByCode = map[string]string{
	"42501": "Gatehouse: this session's person is not authorized for this database",
	"53300": workerCapMessage,
	"57P03": refusalsByReason["not_ready"].message,
	"3D000": refusalsByReason["no_database"].message,
	"28000": notVerifiedMessage,
}

// brokerRefusal is the relay's fixed rewrite of an ErrorResponse the broker
// authored, keeping its severity (ERROR leaves the session open). A known
// reason or code keeps its code; anything else is one generic refusal.
func brokerRefusal(severity string, body []byte) []byte {
	if s := errorField(body, 'S'); s == "ERROR" {
		severity = s
	}
	if r, ok := refusalsByReason[errorField(body, brokercore.RefusalReasonField)]; ok {
		return severityFrame(severity, r.code, r.message)
	}
	code := sqlState(body)
	if message, ok := refusalsByCode[code]; ok {
		return severityFrame(severity, code, message)
	}
	return severityFrame(severity, "08004", genericRefusalMessage)
}

// refusalFrame is the relay-authored FATAL error for a broker startup refusal.
func refusalFrame(body []byte) []byte { return brokerRefusal("FATAL", body) }

// copyPostgres relays an established session. Broker frames are relayed
// whole, so when the broker ends the session (deadline, revocation, a failed
// recheck) at a frame boundary while the worker is still connected, the
// worker gets one relay-authored FATAL frame instead of a silent close.
func copyPostgres(ctx context.Context, client, up net.Conn, deadline time.Time) {
	_ = client.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	// At the task deadline the worker is told; a withdrawn task (cancelled)
	// closes both sides at once.
	stop := context.AfterFunc(ctx, func() {
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_ = client.Close()
		}
		_ = up.Close()
	})
	defer stop()
	var quiet atomic.Bool
	done := make(chan struct{}, 1)
	go func() {
		// The worker closing its side, or the relay closing it (a withdrawn
		// task), ends the session quietly; a deadline or a broker close ends
		// it with the relay's frame.
		if _, e := io.Copy(up, client); e == nil || errors.Is(e, net.ErrClosed) {
			quiet.Store(true)
		}
		_ = up.Close()
		done <- struct{}{}
	}()
	boundary := relayFrames(client, bufio.NewReaderSize(up, 32<<10))
	// A relay that is itself stopping (task withdrawn) closes without a frame.
	withdrawn := ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded)
	if boundary && !quiet.Load() && !withdrawn {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = client.Write(errorFrame("08006", sessionEndedMessage))
	}
	_ = client.Close()
	_ = up.Close()
	<-done
}

// maxBrokerErrorBytes bounds an ErrorResponse the relay inspects. Broker
// refusals are far smaller; larger errors come from the database and stream.
const maxBrokerErrorBytes = 16 << 10

// relayFrames copies whole PostgreSQL backend frames from src to dst. It
// returns true when src ended between frames, the only point where the relay
// may add a frame of its own.
func relayFrames(dst io.Writer, src *bufio.Reader) bool {
	w := bufio.NewWriterSize(dst, 32<<10)
	var head [5]byte
	for {
		if src.Buffered() == 0 && w.Flush() != nil {
			return false
		}
		if n, e := io.ReadFull(src, head[:]); e != nil {
			return n == 0 && w.Flush() == nil
		}
		length := binary.BigEndian.Uint32(head[1:])
		if length < 4 {
			return false
		}
		if head[0] == 'E' && length <= maxBrokerErrorBytes {
			// A database server error passes unchanged; one the broker
			// authored (it carries a reason) is replaced with fixed words.
			body := make([]byte, length-4)
			if _, e := io.ReadFull(src, body); e != nil {
				return false
			}
			frame := append(append([]byte(nil), head[:]...), body...)
			if errorField(body, brokercore.RefusalReasonField) != "" {
				frame = brokerRefusal("FATAL", body)
			}
			if _, e := w.Write(frame); e != nil {
				return false
			}
			continue
		}
		if _, e := w.Write(head[:]); e != nil {
			return false
		}
		if _, e := io.CopyN(w, src, int64(length-4)); e != nil {
			return false
		}
	}
}

// errorFrame builds a FATAL ErrorResponse with relay-authored text only.
func errorFrame(code, message string) []byte { return severityFrame("FATAL", code, message) }

// severityFrame builds an ErrorResponse with relay-authored text only.
func severityFrame(severity, code, message string) []byte {
	var body []byte
	for _, f := range []struct {
		t byte
		v string
	}{{'S', severity}, {'V', severity}, {'C', code}, {'M', message}} {
		body = append(append(append(body, f.t), f.v...), 0)
	}
	return encodePGFrame('E', append(body, 0))
}

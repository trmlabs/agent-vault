package taskrelay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

const cancelCode = 80877102

type cancelTarget struct {
	mu      sync.Mutex
	active  bool
	address string
	packet  []byte
	expiry  time.Time
}

// PostgreSQL uses outer TLS (the sandbox's public-CA stunnel can provide it).
// Only the fixed database/user and a public placeholder are accepted. The relay
// substitutes proof and replaces the broker cancellation key with a local one.
func (r *relay) postgres(conn net.Conn) {
	_ = conn.SetDeadline(minTime(r.config.Deadline, time.Now().Add(handshakeTimeout)))
	if r.admit(r.ctx, conn.RemoteAddr().String(), "postgres") != nil {
		return
	}
	defer func() { _ = r.record("postgres", "terminal") }()
	packet, e := readStartupPacket(conn)
	if e != nil {
		return
	}
	if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
		r.cancelPostgres(conn.RemoteAddr().String(), packet)
		return
	}
	var startup pgproto3.StartupMessage
	if startup.Decode(packet[4:]) != nil || startup.ProtocolVersion != pgproto3.ProtocolVersionNumber {
		return
	}
	c := r.config.Postgres
	if !validStartup(startup.Parameters, c) {
		return
	}
	// Preserve validated client behavior while fixing connection authority to the
	// operator's database/user. Never forward arbitrary backend options.
	parameters := map[string]string{"user": c.User, "database": c.Database}
	for _, key := range []string{"application_name", "statement_timeout", "client_encoding"} {
		if value, ok := startup.Parameters[key]; ok {
			parameters[key] = value
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
	if e != nil || typ != 'p' || string(password) != c.Placeholder+"\x00" {
		return
	}
	proof, expiry, e := readProof(c.Upstream, r.config.Deadline)
	if e != nil {
		return
	}
	if r.pair.check(r.ctx, conn.RemoteAddr().String()) != nil {
		return
	}
	up, e := dialUpstream(r.ctx, c.Upstream)
	if e != nil {
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(handshakeTimeout)))
	if _, e = up.Write(packet); e != nil {
		return
	}
	typ, body, e := readPGFrame(up, 4096)
	if e != nil || typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != 3 {
		return
	}
	if !time.Now().Before(expiry) || r.pair.check(r.ctx, conn.RemoteAddr().String()) != nil {
		return
	}
	authPacket, e := (&pgproto3.PasswordMessage{Password: proof}).Encode(nil)
	if e != nil {
		return
	}
	if _, e = up.Write(authPacket); e != nil {
		return
	}
	// Accumulate the bounded startup response before disclosing anything. Broker
	// authentication failures remain generic; never relay their error text.
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
			return
		}
		switch typ {
		case 'R':
			if authenticated || len(body) != 4 || binary.BigEndian.Uint32(body) != 0 {
				return
			}
			authenticated = true
		case 'S':
			if !authenticated {
				return
			}
		case 'K':
			if !authenticated || len(body) != 8 || remove != nil {
				return
			}
			var local []byte
			local, remove, e = r.registerCancel(body, up.RemoteAddr().String(), expiry)
			if e != nil {
				return
			}
			body = local
		case 'Z':
			if !authenticated || len(body) != 1 {
				return
			}
		default:
			return
		}
		response = append(response, encodePGFrame(typ, body)...)
		if typ == 'Z' {
			break
		}
	}
	if typ != 'Z' || r.pair.check(r.ctx, conn.RemoteAddr().String()) != nil || r.record("postgres", "established") != nil {
		return
	}
	_ = conn.SetDeadline(expiry)
	_ = up.SetDeadline(expiry)
	if _, e = conn.Write(response); e != nil {
		return
	}
	copyTunnel(r.ctx, conn, conn, up, up, expiry)
}

func validStartup(parameters map[string]string, c *PostgresConfig) bool {
	if parameters["database"] != c.Database || parameters["user"] != c.User {
		return false
	}
	for key, value := range parameters {
		switch key {
		case "database", "user":
		case "application_name":
			if len(value) > 63 {
				return false
			}
			for _, char := range value {
				if char < 32 || char > 126 {
					return false
				}
			}
		case "statement_timeout":
			// Accept a positive millisecond value, not units, options or a request
			// to disable the timeout. SQL permissions remain the access boundary.
			if value == "" || len(value) > 10 {
				return false
			}
			for _, char := range value {
				if char < '0' || char > '9' {
					return false
				}
			}
			n, err := strconv.ParseUint(value, 10, 31)
			if err != nil || n == 0 {
				return false
			}
		case "client_encoding":
			if value != "UTF8" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

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

func (r *relay) registerCancel(coreKey []byte, address string, expiry time.Time) ([]byte, func(), error) {
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
		target := &cancelTarget{active: true, address: address, packet: packet, expiry: expiry}
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
func (r *relay) cancelPostgres(peer string, packet []byte) {
	if len(packet) != 16 {
		return
	}
	r.cancelMu.Lock()
	target := r.cancellations[string(packet[8:])]
	r.cancelMu.Unlock()
	if target == nil || !target.mu.TryLock() {
		return
	}
	defer target.mu.Unlock()
	if !target.active || !time.Now().Before(target.expiry) || r.pair.check(r.ctx, peer) != nil {
		return
	}
	// Pin to the established broker socket, not a newly selected service replica.
	c := r.config.Postgres.Upstream
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

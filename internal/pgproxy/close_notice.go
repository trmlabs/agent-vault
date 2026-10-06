package pgproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// closeNotice names why the broker itself ends a session. The client gets it
// as a FATAL ErrorResponse at a message boundary before the connection
// closes, so no broker-initiated close looks like a crashed backend. The
// reason code lets the relay replace the message with fixed words.
type closeNotice struct{ code, reason, message string }

var (
	// noticeRestarting is a planned restart between transactions: reconnect.
	noticeRestarting = closeNotice{"57P01", "restarting", restartingMessage}
	// noticeRestartCut is a planned restart that ended an open transaction,
	// which the database rolls back. It must not look like a clean restart.
	noticeRestartCut = closeNotice{"08006", "restart_cut", "Agent Vault: restarting; this session's open transaction was ended and rolled back"}
	// noticeAuthorization ends a session whose access was revoked or could not
	// be confirmed by the periodic recheck.
	noticeAuthorization = closeNotice{"08006", "authorization_ended", "Agent Vault: access for this session was revoked or could not be confirmed"}
	// noticeDeadline ends a pool worker's session at its Pod's deadline.
	noticeDeadline = closeNotice{"08006", "deadline", "Agent Vault: this worker reached its deadline"}
	// noticeCredential ends a session whose database credential expired.
	noticeCredential = closeNotice{"08006", "credential_expired", "Agent Vault: this session's database credential expired; reconnect"}
	// noticeUpstream ends a session whose database connection failed.
	noticeUpstream = closeNotice{"08006", "upstream", "Agent Vault: the database connection was lost; reconnect"}
	// noticeAudit ends every session when the audit trail fails.
	noticeAudit = closeNotice{"08004", "audit_unavailable", "Agent Vault: audit unavailable"}
	// noticeEncoding ends a session whose server reported a setting change
	// that would make the broker misread later text.
	noticeEncoding = closeNotice{"42501", "encoding_change", lexerChangeMessage}
)

// closeState carries an unpooled session's close notice from whoever ends it
// to the relay that writes it, and whether it reached the client.
type closeState struct {
	notice  atomic.Pointer[closeNotice]
	written atomic.Bool
	sent    atomic.Pointer[closeNotice] // the notice actually written, after any restart_cut swap
}

// logSessionEnd records each session the broker ends itself, and whether the
// client got the notice, so runs can count named and unnamed endings.
func (b *Broker) logSessionEnd(service string, n closeNotice, notified bool) {
	b.logger.Info("pgproxy: session ended by the broker", "reason", n.reason, "code", n.code, "notified", notified, "service", service)
}

// noticeWriteTimeout bounds writing a close notice to a client that is not
// reading, so ending a session never waits on it.
const noticeWriteTimeout = time.Second

// writeNotice writes n to a client connection as one framed FATAL message.
func writeNotice(conn net.Conn, n closeNotice) bool {
	frame, err := brokerError("FATAL", n.code, n.reason, n.message).Encode(nil)
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(noticeWriteTimeout))
	_, err = conn.Write(frame)
	return err == nil
}

// registerCloser lets Shutdown, a failed audit trail or lost cleanup
// authority end an unpooled session with a notice. Pooled sessions are found
// through b.pooled instead.
func (b *Broker) registerCloser(conn net.Conn, end func(closeNotice)) func() {
	b.mu.Lock()
	b.closers[conn] = end
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.closers, conn)
		b.mu.Unlock()
	}
}

// lockWithin takes mu if it frees within d, so a close notice can wait for a
// write in progress to finish its message without waiting on a client that
// has stopped reading.
func lockWithin(mu *sync.Mutex, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !mu.TryLock() {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// endConnLocked ends one connection the broker is closing for its own reason:
// a pooled or unpooled session gets its notice first (between transactions,
// restart becomes restartCut when one is open), anything still in its
// handshake closes at once. Caller holds b.mu; the notice is written off the
// lock so a slow client cannot hold it.
func (b *Broker) endConnLocked(conn net.Conn, n closeNotice) {
	if s := b.pooled[conn]; s != nil {
		go s.killWith(&n)
		return
	}
	if end := b.closers[conn]; end != nil {
		end(n) // records the notice now and ends the session off the lock
		return
	}
	b.logger.Info("pgproxy: connection closed during its handshake without a notice", "reason", n.reason)
	_ = conn.Close()
}

// errorClass names an error's kind for a log line without its text, which
// can carry addresses or database messages.
func errorClass(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "context"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &netErr):
		return "network"
	case errors.Is(err, errPoolBudget):
		return "budget"
	default:
		return "other"
	}
}

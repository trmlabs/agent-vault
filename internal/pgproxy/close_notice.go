package pgproxy

import (
	"net"
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

// noticeWriteTimeout bounds writing a close notice to a client that is not
// reading, so ending a session never waits on it.
const noticeWriteTimeout = time.Second

// writeNotice writes n to a client connection as one framed FATAL message.
func writeNotice(conn net.Conn, n closeNotice) {
	frame, err := brokerError("FATAL", n.code, n.reason, n.message).Encode(nil)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(noticeWriteTimeout))
	_, _ = conn.Write(frame)
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
		go end(n)
		return
	}
	_ = conn.Close()
}

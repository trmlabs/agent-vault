package pgproxy

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// AuditTrail records one row per session event from verified identity only.
// Admit gates new sessions on the trail being writable and checkpointed.
// *auditchain.Chain implements it. A nil trail disables auditing.
type AuditTrail interface {
	Admit() error
	Record(auditchain.Event) error
}

func (b *Broker) auditAdmit() error {
	if b.opts.Audit == nil {
		return nil
	}
	return b.opts.Audit.Admit()
}

func (b *Broker) auditRecord(e auditchain.Event) error {
	if b.opts.Audit == nil {
		return nil
	}
	return b.opts.Audit.Record(e)
}

// auditDenied is best effort: the connection is refused either way, and a
// failed write already stops admission through Admit.
func (b *Broker) auditDenied(e auditchain.Event, outcome string) {
	e.Event, e.Outcome = auditchain.EventDenied, outcome
	_ = b.auditRecord(e)
}

// watchAudit ends every open session when the audit trail fails: Admit
// already refuses new ones, and nothing an open session does could be
// recorded any more.
func (b *Broker) watchAudit() {
	trail, ok := b.opts.Audit.(interface{ Failed() <-chan struct{} })
	if !ok {
		return
	}
	go func() {
		select {
		case <-trail.Failed():
		case <-b.ctx.Done():
			return
		}
		b.logger.Error("pgproxy: audit trail failed; ending open sessions")
		b.mu.Lock()
		for conn := range b.conns {
			_ = conn.Close()
		}
		b.mu.Unlock()
	}()
}

// Unauthenticated clients can cause denied rows, each a synchronous write
// under the chain lock that admission also takes, so those rows are capped.
const (
	deniedPerSecond = 10
	deniedBurst     = 20
	deniedReport    = 10 * time.Second
)

// deniedLimiter is a token bucket for pre-authentication denied rows. Rows it
// drops are counted and reported in the operational log, not the trail.
type deniedLimiter struct {
	mu         sync.Mutex
	tokens     float64
	last       time.Time
	suppressed int
	reported   time.Time
}

func (l *deniedLimiter) allow(now time.Time, logger *slog.Logger) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.tokens = deniedBurst
	} else {
		l.tokens = min(deniedBurst, l.tokens+now.Sub(l.last).Seconds()*deniedPerSecond)
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	l.suppressed++
	if now.Sub(l.reported) >= deniedReport {
		logger.Warn("pgproxy: pre-authentication denied rows rate-limited", slog.Int("suppressed", l.suppressed))
		l.suppressed, l.reported = 0, now
	}
	return false
}

// newSessionID names one client session in the audit trail. It is random,
// not derived from any credential or lease.
func newSessionID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

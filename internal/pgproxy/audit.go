package pgproxy

import (
	"crypto/rand"
	"encoding/hex"

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

// newSessionID names one client session in the audit trail. It is random,
// not derived from any credential or lease.
func newSessionID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

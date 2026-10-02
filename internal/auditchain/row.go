// Package auditchain writes the broker's tamper-evident audit trail: one JSON
// row per event on stdout, chained per replica boot by HMAC and checkpointed by
// a Vault Transit signature, plus the verifier that checks it offline.
package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// RowType tags audit rows so a log sink can select them from other output.
const RowType = "gatehouse.audit.v1"

// Events. Every row is one of these; rows the chain writes itself are
// chain_start, checkpoint, checkpoint_failed and key_rotated.
const (
	EventChainStart       = "chain_start"
	EventSessionOpen      = "session_open"
	EventSessionClose     = "session_close"
	EventDenied           = "denied"
	EventCheckpoint       = "checkpoint"
	EventCheckpointFailed = "checkpoint_failed"
	EventKeyRotated       = "key_rotated"
	EventHTTPRequest      = "http_request"      // admitted, before the upstream call
	EventHTTPResponse     = "http_response"     // outcome and status of that call
	EventTransaction      = "transaction"       // one database transaction on a pooled connection
	EventStateLeak        = "state_leak_caught" // check-in found session state the classifier missed; reset
)

// Row is one audit record. It carries identifiers and fixed outcome codes
// only: never a credential, token, query text or upstream error message.
type Row struct {
	Type      string `json:"type"`
	Replica   string `json:"replica"`
	Boot      uint64 `json:"boot"` // per-replica counter persisted in the store
	Seq       uint64 `json:"seq"`
	Time      string `json:"ts"`
	Event     string `json:"event"`
	Pool      string `json:"pool,omitempty"`      // catalog pool name of the worker
	Agent     string `json:"agent,omitempty"`     // broker agent ID (store UUID)
	PodUID    string `json:"podUID,omitempty"`    // verified runtime instance
	Binding   string `json:"binding,omitempty"`   // vault/service
	Session   string `json:"session,omitempty"`   // broker-generated session ID
	Outcome   string `json:"outcome,omitempty"`   // fixed code
	Requester string `json:"requester,omitempty"` // developer identity, only from a verified source
	// Authorization decision fields (see mitm authorize).
	RequesterKind string `json:"requesterKind,omitempty"` // person, agent, workload or none
	RequesterOID  string `json:"requesterOID,omitempty"`  // Entra object ID of a person
	TokenSHA256   string `json:"tokenSHA256,omitempty"`   // runner session token hash; never the token
	Tier          string `json:"tier,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Groups        string `json:"groups,omitempty"` // required groups checked
	CacheAgeSec   int64  `json:"cacheAgeSec,omitempty"`
	Method        string `json:"method,omitempty"`     // HTTP rows only
	Status        int    `json:"status,omitempty"`     // HTTP response rows: upstream or broker status
	Duration      int64  `json:"durationMs,omitempty"` // transaction rows: milliseconds from first message to completion
	SignedSeq     uint64 `json:"signedSeq,omitempty"`  // checkpoint: the chain head it signs
	SignedMAC     string `json:"signedMAC,omitempty"`
	Signature     string `json:"signature,omitempty"` // checkpoint: Transit "vault:vN:..." signature
	PrevKey       int    `json:"prevKeyVersion,omitempty"`
	// chain_start: the previous boot and its last persisted checkpoint row,
	// so a deleted boot or a truncated tail is detectable.
	PrevBoot          uint64 `json:"prevBoot,omitempty"`
	PrevCheckpointSeq uint64 `json:"prevCheckpointSeq,omitempty"`
	PrevCheckpointMAC string `json:"prevCheckpointMAC,omitempty"`
	KeyVersion        int    `json:"keyVersion"`
	Prev              string `json:"prev"`
	MAC               string `json:"mac"`
}

// macInput encodes every field except MAC with explicit lengths, so no two
// distinct rows share an input regardless of field contents.
func (r Row) macInput() []byte {
	fields := []string{
		r.Type, r.Replica, strconv.FormatUint(r.Boot, 10), strconv.FormatUint(r.Seq, 10), r.Time, r.Event,
		r.Pool, r.Agent, r.PodUID, r.Binding, r.Session, r.Outcome, r.Requester, r.Method, strconv.Itoa(r.Status), strconv.FormatInt(r.Duration, 10),
		strconv.FormatUint(r.SignedSeq, 10), r.SignedMAC, r.Signature,
		strconv.Itoa(r.PrevKey), strconv.FormatUint(r.PrevBoot, 10), strconv.FormatUint(r.PrevCheckpointSeq, 10), r.PrevCheckpointMAC,
		strconv.Itoa(r.KeyVersion), r.Prev,
	}
	return lengthPrefixed("gatehouse-audit-v1", fields...)
}

func (r Row) computeMAC(key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(r.macInput())
	return hex.EncodeToString(h.Sum(nil))
}

// checkpointInput is what Transit signs: the chain identity and its head.
func checkpointInput(replica string, boot, seq uint64, mac string) []byte {
	return lengthPrefixed("gatehouse-checkpoint-v1", replica, strconv.FormatUint(boot, 10), strconv.FormatUint(seq, 10), mac)
}

func lengthPrefixed(domain string, fields ...string) []byte {
	out := append([]byte(domain), 0)
	var n [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}

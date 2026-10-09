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
	EventCertificate      = "proxy_certificate" // a shared proxy was issued its serving certificate
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
	// Identity refusals at the token's signing key: the kid the token
	// claimed ("invalid" plus a 12-hex SHA-256 prefix when it is not a plain
	// identifier) and the connection's peer address. Never the token.
	Kid       string `json:"kid,omitempty"`
	KidSHA256 string `json:"kidSHA256,omitempty"`
	Peer      string `json:"peer,omitempty"`
	// Proxy certificate rows: the issued certificate's serial number in
	// lower-case hex and its notAfter in RFC 3339 UTC.
	Serial   string `json:"serial,omitempty"`
	NotAfter string `json:"notAfter,omitempty"`
	DNSNames string `json:"dnsNames,omitempty"`
	// Refusals: the host, and port when given, the caller asked for, in
	// canonical lower-case form, or "invalid" when it is not a DNS name or IP
	// address. Never a path, query or header.
	Target    string `json:"target,omitempty"`
	Method    string `json:"method,omitempty"`     // HTTP rows only
	Status    int    `json:"status,omitempty"`     // HTTP response rows: upstream or broker status
	Duration  int64  `json:"durationMs,omitempty"` // transaction rows: milliseconds from first message to completion; HTTP response rows: from admission to the end of the response
	SignedSeq uint64 `json:"signedSeq,omitempty"`  // checkpoint: the chain head it signs
	SignedMAC string `json:"signedMAC,omitempty"`
	Signature string `json:"signature,omitempty"` // checkpoint: Transit "vault:vN:..." signature
	PrevKey   int    `json:"prevKeyVersion,omitempty"`
	// chain_start: the previous boot and its last persisted checkpoint row,
	// so a deleted boot or a truncated tail is detectable.
	PrevBoot          uint64 `json:"prevBoot,omitempty"`
	PrevCheckpointSeq uint64 `json:"prevCheckpointSeq,omitempty"`
	PrevCheckpointMAC string `json:"prevCheckpointMAC,omitempty"`
	KeyVersion        int    `json:"keyVersion"`
	Prev              string `json:"prev"`
	// MACVersion selects the MAC input: absent (0) is v1, written before the
	// authorization fields existed; 2 adds them; 3 adds the signing-key
	// refusal fields; 4 adds the proxy certificate fields; MACVersionCurrent
	// (5) adds the refused target and covers every field.
	MACVersion int    `json:"macVersion,omitempty"`
	MAC        string `json:"mac"`
}

// MACVersionCurrent is the MAC input every new row uses.
const MACVersionCurrent = 5

// macInput encodes every field except MAC with explicit lengths, so no two
// distinct rows share an input regardless of field contents. Version 2 adds
// the authorization fields and the version itself, and version 3 the
// signing-key refusal fields, and version 4 the proxy certificate fields, and
// version 5 the refused target. Older versions are kept only to verify rows
// written before them, and a row carrying a field its version's MAC does not
// cover fails verification (see v2Only through v5Only).
func (r Row) macInput() []byte {
	fields := []string{
		r.Type, r.Replica, strconv.FormatUint(r.Boot, 10), strconv.FormatUint(r.Seq, 10), r.Time, r.Event,
		r.Pool, r.Agent, r.PodUID, r.Binding, r.Session, r.Outcome, r.Requester, r.Method, strconv.Itoa(r.Status), strconv.FormatInt(r.Duration, 10),
		strconv.FormatUint(r.SignedSeq, 10), r.SignedMAC, r.Signature,
		strconv.Itoa(r.PrevKey), strconv.FormatUint(r.PrevBoot, 10), strconv.FormatUint(r.PrevCheckpointSeq, 10), r.PrevCheckpointMAC,
		strconv.Itoa(r.KeyVersion), r.Prev,
	}
	if r.MACVersion < 2 {
		return lengthPrefixed("gatehouse-audit-v1", fields...)
	}
	fields = append(fields, strconv.Itoa(r.MACVersion),
		r.RequesterKind, r.RequesterOID, r.TokenSHA256, r.Tier, r.Decision, r.Groups, strconv.FormatInt(r.CacheAgeSec, 10))
	if r.MACVersion < 3 {
		return lengthPrefixed("gatehouse-audit-v2", fields...)
	}
	fields = append(fields, r.Kid, r.KidSHA256, r.Peer)
	if r.MACVersion < 4 {
		return lengthPrefixed("gatehouse-audit-v3", fields...)
	}
	fields = append(fields, r.Serial, r.NotAfter, r.DNSNames)
	if r.MACVersion < 5 {
		return lengthPrefixed("gatehouse-audit-v4", fields...)
	}
	fields = append(fields, r.Target)
	return lengthPrefixed("gatehouse-audit-v5", fields...)
}

// v2Only reports whether a row sets a field that only the v2 MAC covers.
func (r Row) v2Only() bool {
	return r.RequesterKind != "" || r.RequesterOID != "" || r.TokenSHA256 != "" || r.Tier != "" ||
		r.Decision != "" || r.Groups != "" || r.CacheAgeSec != 0
}

// v3Only reports whether a row sets a field that only the v3 MAC covers.
func (r Row) v3Only() bool { return r.Kid != "" || r.KidSHA256 != "" || r.Peer != "" }

// v4Only reports whether a row sets a field that only the v4 MAC covers.
func (r Row) v4Only() bool { return r.Serial != "" || r.NotAfter != "" || r.DNSNames != "" }

// v5Only reports whether a row sets a field that only the v5 MAC covers.
func (r Row) v5Only() bool { return r.Target != "" }

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

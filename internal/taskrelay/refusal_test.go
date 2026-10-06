package taskrelay

import (
	"bytes"
	"net"
	"testing"
)

// refusedWithError reports whether the relay refused: it either closed at once
// or sent one ErrorResponse and then closed. Nothing else may follow.
func refusedWithError(c net.Conn) bool {
	typ, _, e := readPGFrame(c, 4096)
	if e != nil {
		return true
	}
	if typ != 'E' {
		return false
	}
	_, e = c.Read(make([]byte, 1))
	return e != nil
}

func errorBody(code, message string) []byte {
	var b []byte
	for _, f := range [][2]string{{"S", "FATAL"}, {"C", code}, {"M", message}} {
		b = append(append(append(b, f[0][0]), f[1]...), 0)
	}
	return append(b, 0)
}

// reasonBody is an ErrorResponse body as the broker authors it: with its
// reason code and its own text, which must never reach the worker.
func reasonBody(severity, code, reason string) []byte {
	var b []byte
	for _, f := range [][2]string{{"S", severity}, {"C", code}, {"M", "Agent Vault: broker detail that must not leak"}, {"G", reason}} {
		b = append(append(append(b, f[0][0]), f[1]...), 0)
	}
	return append(b, 0)
}

// Each broker reason reaches the worker as its code and fixed words.
func TestBrokerReasonsBecomeFixedWords(t *testing.T) {
	for reason, want := range map[string][2]string{
		"actor_limit":              {"53300", "this worker reached its session cap"},
		"database_limit":           {"53300", "the database's Gatehouse connection budget is full; retry shortly"},
		"pool_budget":              {"53300", "the database's Gatehouse connection budget is full; retry shortly"},
		"capacity":                 {"53300", "Gatehouse is at capacity; retry shortly"},
		"pinned_share":             {"53300", "no session-mode database connection is free"},
		"not_ready":                {"57P03", "Gatehouse is starting; retry in a few seconds"},
		"no_database":              {"3D000", "this database isn't in the Gatehouse catalog for your pool"},
		"authentication":           {"28000", "Gatehouse could not verify this worker"},
		"upstream":                 {"08006", "Gatehouse could not reach the database; retry"},
		"credential":               {"08006", "Gatehouse could not get a database credential; retry shortly"},
		"restarting":               {"57P01", "Gatehouse is restarting; reconnect"},
		"restart_cut":              {"08006", "Gatehouse restarted while a transaction was open"},
		"authorization_ended":      {"08006", "access was revoked or could not be confirmed"},
		"deadline":                 {"08006", "this worker reached its deadline"},
		"credential_expired":       {"08006", "its database credential expired"},
		"role_change":              {"42501", "Gatehouse refuses ALTER ROLE, ALTER USER and ALTER DATABASE"},
		"read_only":                {"25006", "this database login is read-only: Gatehouse allows only reads"},
		"encoding_change":          {"42501", "Gatehouse refuses changing standard_conforming_strings or client_encoding"},
		"pipelined_escape":         {"0A000", "Gatehouse refuses a statement with a backslash after an Execute"},
		"statement_limit":          {"54000", "too many prepared statements"},
		"not_entitled":             {"42501", "this person is not entitled to this database"},
		"no_person":                {"42501", "no person could be named for this session"},
		"audit_unavailable":        {"08004", "could not write its audit record"},
		"ledger_unavailable":       {"08004", "could not record the session in its accounting"},
		"pool_external":            {"42501", "may reach only external destinations"},
		"pool_ceiling":             {"42501", "above your pool's tier ceiling"},
		"entitlement_config":       {"42501", "entitlement settings are incomplete"},
		"workload_not_entitled":    {"42501", "this workload is not entitled"},
		"no_identity":              {"42501", "no identity that can be authorized"},
		"entitlement_rate_limited": {"42501", "(rate limited); retry shortly"},
		"entitlement_unavailable":  {"42501", "could not check entitlements just now"},
		"account_disabled":         {"42501", "account is disabled"},
		"session_unexpected":       {"42501", "takes no runner session"},
		"session_unverifiable":     {"42501", "could not verify this runner session"},
		"session_token":            {"42501", "runner session's token was refused"},
		"session_pool":             {"42501", "belongs to another pool"},
		"session_unbindable":       {"42501", "could not bind this runner session"},
		"session_pod_mismatch":     {"42501", "already bound to another Pod"},
		"requester_unverifiable":   {"42501", "could not verify the person behind this session"},
		// A reason with no words of its own keeps its code and is named.
		"some_new_check": {"42501", "not authorized for this database (some_new_check)"},
	} {
		// Authorization decisions have many reasons and one code, 42501.
		frame := refusalFrame(reasonBody("FATAL", want[0], reason))
		if frame[0] != 'E' || sqlState(frame[5:]) != want[0] || !bytes.Contains(frame, []byte(want[1])) || bytes.Contains(frame, []byte("must not leak")) {
			t.Errorf("%s: frame %q", reason, frame)
		}
	}
}

// Without a reason (an older broker), the known codes still keep fixed words.
func TestKnownBrokerRefusalsKeepTheirCodeWithFixedText(t *testing.T) {
	for code, want := range map[string]string{
		"57P03": "Gatehouse is starting; retry in a few seconds",
		"3D000": "this database isn't in the Gatehouse catalog for your pool",
		"28000": "Gatehouse could not verify this worker",
		"53300": "this worker reached its session cap",
		"42501": "not authorized for this database",
	} {
		frame := refusalFrame(errorBody(code, "detail the broker must not leak"))
		if frame[0] != 'E' || sqlState(frame[5:]) != code || !bytes.Contains(frame, []byte(want)) || bytes.Contains(frame, []byte("must not leak")) {
			t.Errorf("%s: frame %q", code, frame)
		}
	}
}

func TestOtherBrokerErrorsBecomeOneGenericRefusal(t *testing.T) {
	for _, body := range [][]byte{errorBody("XX000", "detail the broker must not leak"), errorBody("08006", "detail the broker must not leak"),
		reasonBody("FATAL", "08004", "audit_unavailable"), reasonBody("FATAL", "08004", "ledger_unavailable")} {
		frame := refusalFrame(body)
		if sqlState(frame[5:]) != "08004" || bytes.Contains(frame, []byte("must not leak")) {
			t.Fatalf("frame %q", frame)
		}
	}
	if sqlState([]byte{'C'}) != "" {
		t.Fatal("malformed body parsed")
	}
}

func TestErrorFrameCarriesCodeAndMessage(t *testing.T) {
	frame := errorFrame("28P01", "Gatehouse: wrong placeholder password for this binding")
	if sqlState(frame[5:]) != "28P01" || !bytes.Contains(frame, []byte("wrong placeholder")) {
		t.Fatalf("frame %q", frame)
	}
}

// Every reason the broker sends has words here, so the client and the relay
// log can tell failures apart; an unknown or malformed reason is never echoed
// unless it has the shape of a code.
func TestEveryBrokerReasonHasWords(t *testing.T) {
	for _, reason := range []string{"actor_limit", "audit_unavailable", "authentication", "capacity", "credential", "database_limit",
		"ledger_unavailable", "no_database", "not_ready", "read_only", "upstream", "authorization_ended", "credential_expired", "deadline",
		"restart_cut", "restarting", "encoding_change", "role_change", "pipelined_escape", "statement_limit", "pinned_share", "pool_budget"} {
		if _, ok := refusalsByReason[reason]; !ok {
			t.Errorf("no words for broker reason %s", reason)
		}
	}
	frame := refusalFrame(reasonBody("FATAL", "XX000", "Bad Reason; DROP"))
	if bytes.Contains(frame, []byte("Bad Reason")) || sqlState(frame[5:]) != "08004" {
		t.Fatalf("malformed reason echoed: %q", frame)
	}
	if got := refusalReason(reasonBody("FATAL", "08004", "ledger_unavailable")); got != "ledger_unavailable" {
		t.Fatalf("log reason %q", got)
	}
	if got := refusalReason(errorBody("XX000", "x")); got != "sqlstate_XX000" {
		t.Fatalf("log reason without a code %q", got)
	}
}

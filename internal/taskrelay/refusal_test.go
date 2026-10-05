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
		"actor_limit":      {"53300", "this worker reached its session cap"},
		"database_limit":   {"53300", "the database's Gatehouse connection budget is full; retry shortly"},
		"pool_budget":      {"53300", "the database's Gatehouse connection budget is full; retry shortly"},
		"capacity":         {"53300", "Gatehouse is at capacity; retry shortly"},
		"pinned_share":     {"53300", "no session-mode database connection is free"},
		"not_ready":        {"57P03", "Gatehouse is starting; retry in a few seconds"},
		"no_database":      {"3D000", "this database isn't in the Gatehouse catalog for your pool"},
		"authentication":   {"28000", "Gatehouse could not verify this worker"},
		"upstream":         {"08006", "Gatehouse could not reach the database; retry"},
		"credential":       {"08006", "Gatehouse could not get a database credential; retry shortly"},
		"restarting":       {"57P01", "Gatehouse is restarting; reconnect"},
		"role_change":      {"42501", "Gatehouse refuses ALTER ROLE, ALTER USER and ALTER DATABASE"},
		"read_only":        {"25006", "this database login is read-only: Gatehouse allows only reads"},
		"encoding_change":  {"42501", "Gatehouse refuses changing standard_conforming_strings or client_encoding"},
		"pipelined_escape": {"0A000", "Gatehouse refuses a statement with a backslash after an Execute"},
		"statement_limit":  {"54000", "too many prepared statements"},
		"not_entitled":     {"42501", "not authorized for this database"},
		"no_person":        {"42501", "not authorized for this database"},
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

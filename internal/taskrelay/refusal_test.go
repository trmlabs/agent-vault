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

func TestCapacityRefusalKeepsItsCode(t *testing.T) {
	frame := refusalFrame(sqlState(errorBody("53300", "Agent Vault: too many concurrent database sessions")))
	if frame[0] != 'E' || sqlState(frame[5:]) != "53300" || !bytes.Contains(frame, []byte("too many concurrent database sessions for this worker")) {
		t.Fatalf("frame %q", frame)
	}
}

func TestAuthorizationRefusalKeepsItsCodeNotItsDetail(t *testing.T) {
	frame := refusalFrame(sqlState(errorBody("42501", "Agent Vault: not authorized for database \"x\" (not_entitled)")))
	if sqlState(frame[5:]) != "42501" || !bytes.Contains(frame, []byte("not authorized for this database")) || bytes.Contains(frame, []byte("not_entitled")) {
		t.Fatalf("frame %q", frame)
	}
}

// A developer can tell the actionable refusals apart, in the relay's words.
func TestKnownBrokerRefusalsKeepTheirCodeWithFixedText(t *testing.T) {
	for code, want := range map[string]string{
		"57P03": "Gatehouse is starting; retry in a few seconds",
		"3D000": "this database isn't in the Gatehouse catalog for your pool",
		"28000": "Gatehouse could not verify this worker",
		"53300": "too many concurrent database sessions for this worker",
		"42501": "not authorized for this database",
	} {
		frame := refusalFrame(sqlState(errorBody(code, "detail the broker must not leak")))
		if frame[0] != 'E' || sqlState(frame[5:]) != code || !bytes.Contains(frame, []byte(want)) || bytes.Contains(frame, []byte("must not leak")) {
			t.Errorf("%s: frame %q", code, frame)
		}
	}
}

func TestOtherBrokerErrorsBecomeOneGenericRefusal(t *testing.T) {
	for _, code := range []string{"XX000", "08006", "08004"} {
		frame := refusalFrame(sqlState(errorBody(code, "detail the broker must not leak")))
		if sqlState(frame[5:]) != "08004" || bytes.Contains(frame, []byte("must not leak")) {
			t.Fatalf("%s: frame %q", code, frame)
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

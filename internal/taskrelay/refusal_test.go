package taskrelay

import (
	"bytes"
	"testing"
)

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

func TestOtherBrokerErrorsBecomeOneGenericRefusal(t *testing.T) {
	frame := refusalFrame(sqlState(errorBody("28000", "detail the broker must not leak")))
	if sqlState(frame[5:]) != "08004" || bytes.Contains(frame, []byte("must not leak")) {
		t.Fatalf("frame %q", frame)
	}
	if sqlState([]byte{'C'}) != "" {
		t.Fatal("malformed body parsed")
	}
}

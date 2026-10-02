package brokercore

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

var loopback = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

func TestReadProxyV1ReturnsSourceAndLeavesTheRest(t *testing.T) {
	r := bytes.NewReader([]byte("PROXY TCP4 10.244.0.9 10.244.0.5 51234 15443\r\nSTARTUP"))
	got, err := ReadProxyV1(r, loopback)
	if err != nil || got != netip.MustParseAddr("10.244.0.9") {
		t.Fatalf("got %v err %v", got, err)
	}
	rest := make([]byte, 7)
	if _, err := r.Read(rest); err != nil || string(rest) != "STARTUP" {
		t.Fatal("header reader consumed client bytes")
	}
}

func TestReadProxyV1Refusals(t *testing.T) {
	cases := map[string]struct {
		header string
		remote net.Addr
	}{
		"non-loopback terminator": {"PROXY TCP4 10.0.0.9 10.0.0.5 1 2\r\n", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 1}},
		"unknown":                 {"PROXY UNKNOWN\r\n", loopback},
		"family mismatch":         {"PROXY TCP6 10.0.0.9 10.0.0.5 1 2\r\n", loopback},
		"bad port":                {"PROXY TCP4 10.0.0.9 10.0.0.5 0 2\r\n", loopback},
		"leading zero port":       {"PROXY TCP4 10.0.0.9 10.0.0.5 01 2\r\n", loopback},
		"no terminator":           {"PROXY TCP4 10.0.0.9 10.0.0.5 1 2", loopback},
		"overlong":                {"PROXY TCP4 " + string(bytes.Repeat([]byte("1"), 120)) + "\r\n", loopback},
		"client protocol first":   {"\x00\x00\x00\x08\x04\xd2\x16\x2f", loopback},
		"zone":                    {"PROXY TCP6 fe80::1%eth0 fe80::2 1 2\r\n", loopback},
	}
	for name, c := range cases {
		if _, err := ReadProxyV1(bytes.NewReader([]byte(c.header)), c.remote); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

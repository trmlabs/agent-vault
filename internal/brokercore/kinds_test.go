package brokercore

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestKindedConnReadsItsPrefixFirst(t *testing.T) {
	client, server := net.Pipe()
	go func() { _, _ = io.WriteString(client, "rest"); _ = client.Close() }()
	c := &KindedConn{Conn: server, Kinds: []string{KindProxyAttested}, Prefix: strings.NewReader("head-")}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "head-rest" {
		t.Fatalf("read %q %v", b, err)
	}
	if !KindAdmitted(ConnKinds(c), KindProxyAttested) || KindAdmitted(ConnKinds(c), KindPodToken) {
		t.Fatal("tagged connection admits the wrong kinds")
	}
	if KindAdmitted(ConnKinds(server), KindProxyAttested) || !KindAdmitted(ConnKinds(server), KindPodToken) || !KindAdmitted(ConnKinds(nil), "") {
		t.Fatal("untagged connection admits the wrong kinds")
	}
}

package taskrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// tcpPair returns two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	a, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	b := <-accepted
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// session runs copyPostgres between a worker end and a broker end and
// returns the far sides: what the worker reads, and what the broker writes.
func session(t *testing.T, deadline time.Time) (worker, broker net.Conn) {
	t.Helper()
	worker, relayClient := tcpPair(t)
	relayUp, broker := tcpPair(t)
	go copyPostgres(context.Background(), relayClient, relayUp, deadline)
	_ = worker.SetDeadline(time.Now().Add(5 * time.Second))
	return worker, broker
}

func TestBrokerEndingASessionTellsTheWorker(t *testing.T) {
	worker, broker := session(t, time.Now().Add(time.Minute))
	ready := encodePGFrame('Z', []byte{'I'})
	_, _ = broker.Write(ready)
	broker.Close() // a failed recheck: the broker closes between frames
	if typ, body, e := readPGFrame(worker, 4096); e != nil || typ != 'Z' || !bytes.Equal(body, []byte{'I'}) {
		t.Fatalf("relayed frame %q %q %v", typ, body, e)
	}
	typ, body, e := readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "08006" || !bytes.Contains(body, []byte(sessionEndedMessage)) {
		t.Fatalf("session end frame %q %q %v", typ, body, e)
	}
}

func TestSessionDeadlineTellsTheWorker(t *testing.T) {
	worker, _ := session(t, time.Now().Add(200*time.Millisecond))
	typ, body, e := readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "08006" {
		t.Fatalf("deadline frame %q %q %v", typ, body, e)
	}
}

func TestBrokerClosingMidFrameAddsNothing(t *testing.T) {
	worker, broker := session(t, time.Now().Add(time.Minute))
	frame := encodePGFrame('D', bytes.Repeat([]byte{'x'}, 64))
	_, _ = broker.Write(frame[:20])
	broker.Close()
	got := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for {
		n, e := worker.Read(buf)
		got = append(got, buf[:n]...)
		if e != nil {
			break
		}
	}
	if bytes.Contains(got, []byte("08006")) {
		t.Fatalf("relay wrote a frame inside a partial frame: %q", got)
	}
}

func TestLargeFramesRelayWhole(t *testing.T) {
	worker, broker := session(t, time.Now().Add(time.Minute))
	body := bytes.Repeat([]byte{'y'}, 1<<20)
	go func() { _, _ = broker.Write(encodePGFrame('D', body)) }()
	head := make([]byte, 5)
	if _, e := readFull(worker, head); e != nil || head[0] != 'D' || binary.BigEndian.Uint32(head[1:]) != uint32(len(body)+4) {
		t.Fatalf("header %q %v", head, e)
	}
	got := make([]byte, len(body))
	if _, e := readFull(worker, got); e != nil || !bytes.Equal(got, body) {
		t.Fatal("large frame not relayed intact")
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, e := c.Read(b[n:])
		n += m
		if e != nil {
			return n, e
		}
	}
	return n, nil
}

// An unreachable broker is named, not a silent close.
func TestUnreachableBrokerIsNamed(t *testing.T) {
	f := newRelayFixture(t)
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, freeAddress(t)), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	c := f.dial(t, f.c.Postgres.Listen)
	b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "canary"}}).Encode(nil)
	_, _ = c.Write(b)
	if typ, body, e := readPGFrame(c, 1024); e != nil || typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
		t.Fatal("startup refused")
	}
	_, _ = c.Write(encodePGFrame('p', []byte("public-placeholder\x00")))
	typ, body, e := readPGFrame(c, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "08001" || !bytes.Contains(body, []byte(unreachableMessage)) {
		t.Fatalf("unreachable frame %q %q %v", typ, body, e)
	}
}

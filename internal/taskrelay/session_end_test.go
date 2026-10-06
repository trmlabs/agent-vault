package taskrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
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
	go copyPostgres(context.Background(), relayClient, relayUp, deadline, &ending{})
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

func TestTaskDeadlineMidSessionTellsTheWorker(t *testing.T) {
	worker, relayClient := tcpPair(t)
	relayUp, _ := tcpPair(t)
	deadline := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	go copyPostgres(ctx, relayClient, relayUp, deadline, &ending{})
	_ = worker.SetDeadline(time.Now().Add(5 * time.Second))
	typ, body, e := readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "08006" || !bytes.Contains(body, []byte(sessionEndedMessage)) {
		t.Fatalf("task deadline frame %q %q %v", typ, body, e)
	}
}

func TestWithdrawnTaskClosesSilently(t *testing.T) {
	worker, relayClient := tcpPair(t)
	relayUp, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	go copyPostgres(ctx, relayClient, relayUp, time.Now().Add(time.Minute), &ending{})
	time.Sleep(50 * time.Millisecond)
	cancel()
	_ = worker.SetDeadline(time.Now().Add(5 * time.Second))
	if typ, body, e := readPGFrame(worker, 4096); e == nil {
		t.Fatalf("withdrawn task sent %q %q", typ, body)
	}
}

// In session, a broker refusal is rewritten in fixed words with its severity
// kept; a database server error passes through byte for byte.
func TestInSessionErrors(t *testing.T) {
	worker, broker := session(t, time.Now().Add(time.Minute))
	server := errorBody("42601", `syntax error at or near "SELEC"`)
	serverFrame := encodePGFrame('E', server)
	large := encodePGFrame('E', append(errorBody("XX000", "x"), bytes.Repeat([]byte{'z'}, 20<<10)...))
	go func() {
		_, _ = broker.Write(encodePGFrame('E', reasonBody("ERROR", "53300", "pool_budget")))
		_, _ = broker.Write(encodePGFrame('Z', []byte{'I'}))
		_, _ = broker.Write(serverFrame)
		_, _ = broker.Write(large)
		_, _ = broker.Write(encodePGFrame('E', reasonBody("FATAL", "08006", "upstream")))
	}()
	typ, body, e := readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || errorField(body, 'S') != "ERROR" || sqlState(body) != "53300" ||
		!bytes.Contains(body, []byte("connection budget is full")) || bytes.Contains(body, []byte("must not leak")) {
		t.Fatalf("pooled budget refusal %q %q %v", typ, body, e)
	}
	if typ, _, e := readPGFrame(worker, 16); e != nil || typ != 'Z' {
		t.Fatal("session did not continue after an ERROR refusal")
	}
	got := make([]byte, len(serverFrame))
	if _, e := readFull(worker, got); e != nil || !bytes.Equal(got, serverFrame) {
		t.Fatalf("database error changed: %q", got)
	}
	got = make([]byte, len(large))
	if _, e := readFull(worker, got); e != nil || !bytes.Equal(got, large) {
		t.Fatal("large database error changed")
	}
	typ, body, e = readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || errorField(body, 'S') != "FATAL" || sqlState(body) != "08006" || bytes.Contains(body, []byte("must not leak")) {
		t.Fatalf("in-session upstream loss %q %q %v", typ, body, e)
	}
}

// The sidecar's own proof is unreadable: the worker hears it, not a silent close.
func TestUnreadableProofIsNamed(t *testing.T) {
	f := newRelayFixture(t)
	up := f.upstream(t, freeAddress(t))
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: up, Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	if e := os.Remove(up.ProofFile); e != nil {
		t.Fatal(e)
	}
	c := f.dial(t, f.c.Postgres.Listen)
	b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "canary"}}).Encode(nil)
	_, _ = c.Write(b)
	if typ, body, e := readPGFrame(c, 1024); e != nil || typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
		t.Fatal("startup refused")
	}
	_, _ = c.Write(encodePGFrame('p', []byte("public-placeholder\x00")))
	typ, body, e := readPGFrame(c, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "28000" || !bytes.Contains(body, []byte(notVerifiedMessage)) {
		t.Fatalf("unreadable proof frame %q %q %v", typ, body, e)
	}
}

// A session the broker ends with its own FATAL (a planned restart, a lost
// upstream) is told once: the relay adds no second ending after it.
func TestBrokerFatalIsTheOnlyEnding(t *testing.T) {
	worker, broker := session(t, time.Now().Add(time.Minute))
	_, _ = broker.Write(encodePGFrame('E', reasonBody("FATAL", "08006", "upstream")))
	broker.Close()
	typ, body, e := readPGFrame(worker, 4096)
	if e != nil || typ != 'E' || sqlState(body) != "08006" || !bytes.Contains(body, []byte("could not reach the database")) {
		t.Fatalf("broker ending %q %q %v", typ, body, e)
	}
	if typ, body, e := readPGFrame(worker, 4096); e == nil {
		t.Fatalf("a second ending followed: %q %q", typ, body)
	}
}

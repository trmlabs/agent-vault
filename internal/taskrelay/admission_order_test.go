package taskrelay

import (
	"bytes"
	"crypto/tls"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func countAuditOutcome(t *testing.T, path, outcome string) int {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return bytes.Count(b, []byte(`"outcome":"`+outcome+`"`))
}

// TestBareConnectPerformsNoAdmission proves that a connection which has not
// completed protocol validation costs the relay no Kubernetes request and no
// durable "admitted" row. Bare connects leave nothing in the journal; a wrong
// placeholder or a wrong startup leaves a "denied" row and nothing else.
func TestBareConnectPerformsNoAdmission(t *testing.T) {
	f := newRelayFixture(t)
	var upstreamAccepts atomic.Int32
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			upstreamAccepts.Add(1)
			c.Close()
		}
	}()
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, l.Addr().String()), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	// start's readiness probe is itself a bare connect; it must not have been
	// admitted either.
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("readiness probe produced %d admitted rows", n)
	}

	// Every request the supervisor's one-second pair check could account for
	// over the window, plus one for a tick straddling either edge.
	supervisorBudget := func(elapsed time.Duration) int32 { return int32(elapsed/pairInterval) + 1 }

	// Case 1: 20 bare TCP connects that close without sending a byte.
	before := f.kubeCalls.Load()
	started := time.Now()
	for i := 0; i < 20; i++ {
		c, e := net.DialTimeout("tcp", f.c.Postgres.Listen, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	// Let the handlers observe EOF and return before reading the counters.
	time.Sleep(200 * time.Millisecond)
	if grew, budget := f.kubeCalls.Load()-before, supervisorBudget(time.Since(started)); grew > budget {
		t.Fatalf("bare connects drove %d Kubernetes requests; supervisor alone accounts for at most %d", grew, budget)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("bare connects produced %d admitted rows", n)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "denied:bad-startup"); n != 0 {
		t.Fatalf("bare connects produced %d denied rows; a peer that sent nothing should leave no trace", n)
	}

	// Case 2: a valid TLS startup with the wrong placeholder password.
	before = f.kubeCalls.Load()
	started = time.Now()
	c := f.dial(t, f.c.Postgres.Listen)
	b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "canary"}}).Encode(nil)
	c.Write(b)
	if typ, _, e := readPGFrame(c, 1024); e != nil || typ != 'R' {
		t.Fatal("valid startup was not offered authentication")
	}
	c.Write(encodePGFrame('p', []byte("attacker-proof\x00")))
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("accepted nonplaceholder")
	}
	c.Close()
	if grew, budget := f.kubeCalls.Load()-before, supervisorBudget(time.Since(started)); grew > budget {
		t.Fatalf("wrong placeholder drove %d Kubernetes requests before admission", grew)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "denied:placeholder"); n != 1 {
		t.Fatalf("wrong placeholder produced %d denied:placeholder rows, want 1", n)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("wrong placeholder produced %d admitted rows", n)
	}

	// Case 3: a startup that asserts the wrong authority is denied with its own
	// reason, so the journal separates probing from use.
	c = f.dial(t, f.c.Postgres.Listen)
	b, _ = (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "other"}}).Encode(nil)
	c.Write(b)
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("accepted wrong database")
	}
	c.Close()
	if n := countAuditOutcome(t, f.c.AuditFile, "denied:bad-startup"); n != 1 {
		t.Fatalf("wrong database produced %d denied:bad-startup rows, want 1", n)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("denied startups produced %d admitted rows", n)
	}
	// Case 4: a partial startup length prefix then close. Bytes were sent, so
	// this is a malformed startup, not a bare connect, and leaves one row.
	c = f.dial(t, f.c.Postgres.Listen)
	c.Write([]byte{0, 0})
	c.Close()
	waitFor(t, time.Second, func() bool { return countAuditOutcome(t, f.c.AuditFile, "denied:bad-startup") == 2 })
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("partial startup produced %d admitted rows", n)
	}
	if upstreamAccepts.Load() != 0 {
		t.Fatal("a denied connection reached the upstream")
	}
}

func waitFor(t *testing.T, limit time.Duration, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(limit); time.Now().Before(end); {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// TestForeignPeerDeniedBeforeHandshake pairs the relay with 127.0.0.2 so every
// loopback connection is foreign. Such a peer is refused before the TLS
// handshake, costs no Kubernetes request, and is journaled once, not per
// connect.
func TestForeignPeerDeniedBeforeHandshake(t *testing.T) {
	f := newRelayFixture(t)
	f.c.Sandbox.PodIP = "127.0.0.2"
	f.state.Store(4) // the synthetic API server reports podIP 127.0.0.2
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, l.Addr().String()), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	before := f.kubeCalls.Load()
	started := time.Now()
	for i := 0; i < 5; i++ {
		tc, e := clientTLS(f.c.TLSCertFile, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.c.Postgres.Listen, tc); e == nil {
			c.Close()
			t.Fatal("foreign peer completed a TLS handshake")
		}
	}
	waitFor(t, time.Second, func() bool { return countAuditOutcome(t, f.c.AuditFile, "denied:peer") == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := countAuditOutcome(t, f.c.AuditFile, "denied:peer"); n != 1 {
		t.Fatalf("readiness probe plus 5 foreign connects produced %d denied:peer rows, want exactly 1", n)
	}
	if n := countAuditOutcome(t, f.c.AuditFile, "admitted"); n != 0 {
		t.Fatalf("foreign peers produced %d admitted rows", n)
	}
	if grew, budget := f.kubeCalls.Load()-before, int32(time.Since(started)/pairInterval)+1; grew > budget {
		t.Fatalf("foreign peers drove %d Kubernetes requests; supervisor alone accounts for at most %d", grew, budget)
	}
}

// TestPeerMatchesIsPureAndCheckStillUsesIt keeps the split honest: peerMatches
// makes no network call, and check still refuses a foreign peer.
func TestPeerMatchesIsPureAndCheckStillUsesIt(t *testing.T) {
	f := newRelayFixture(t)
	p, e := newPairVerifier(f.c)
	if e != nil {
		t.Fatal(e)
	}
	before := f.kubeCalls.Load()
	if !p.peerMatches("127.0.0.1:5000") || p.peerMatches("127.0.0.2:5000") || p.peerMatches("not-an-address") {
		t.Fatal("peerMatches disagrees with the pairing")
	}
	if f.kubeCalls.Load() != before {
		t.Fatal("peerMatches made a Kubernetes request")
	}
	if p.check(t.Context(), "127.0.0.2:5000") == nil {
		t.Fatal("check admitted a foreign peer")
	}
	if f.kubeCalls.Load() != before {
		t.Fatal("check consulted the API server for a peer that could never match")
	}
}

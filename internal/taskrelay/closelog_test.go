package taskrelay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink several goroutines write to.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	sink := &syncBuffer{}
	logOutput = sink
	t.Cleanup(func() { logOutput = io.Discard })
	return sink
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// Every ended tunnel is logged with why: the agent closing is INFO; the
// broker side failing is WARN, and when it takes many sessions at once (its
// TLS front killed) that is also one event with the count.
func TestTunnelEndsAreLoggedWithTheirReason(t *testing.T) {
	sink := captureLog(t)
	broker := newActivityBroker(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		c.Connect.Routes, c.Connect.AllowedTargets = routesBroker, nil
		c.Connect.Upstream = broker.upstream(c.Connect.Upstream)
	})
	c, _, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	c.Close()
	waitUntil(t, "the agent's close", func() bool { return len(sink.lines(t, "session_closed")) == 1 })
	first := sink.lines(t, "session_closed")[0]
	if first["reason"] != endClientClosed || first["level"] != "INFO" || first["protocol"] != "connect" || first["target"] != "approved.test:443" {
		t.Fatalf("agent close: %v", first)
	}
	// Six tunnels open, then the broker's side drops them all at once.
	for i := 0; i < 6; i++ {
		if _, _, status := sf.connect(t, ""); status != 200 {
			t.Fatalf("tunnel %d: %d", i, status)
		}
	}
	broker.dropTunnels()
	waitUntil(t, "every broker-side end", func() bool { return len(sink.lines(t, "session_closed")) == 7 })
	for _, line := range sink.lines(t, "session_closed")[1:] {
		if line["reason"] != endUpstreamReset || line["level"] != "WARN" {
			t.Fatalf("a reset tunnel logged as %v", line)
		}
	}
	waitUntil(t, "the one upstream event", func() bool { return len(sink.lines(t, "upstream_dropped_sessions")) == 1 })
	event := sink.lines(t, "upstream_dropped_sessions")[0]
	if event["sessions"] != float64(6) || event["level"] != "WARN" || event["upstream"] != sf.f.c.Connect.Upstream.Address {
		t.Fatalf("upstream event: %v", event)
	}
	time.Sleep(massCloseWindow + 200*time.Millisecond)
	if n := len(sink.lines(t, "upstream_dropped_sessions")); n != 1 {
		t.Fatalf("%d upstream events for one drop", n)
	}
}

// An unreachable upstream is named once, not per refused connection, and its
// return once.
func TestUpstreamUnreachableIsLoggedOnce(t *testing.T) {
	sink := captureLog(t)
	broker := newActivityBroker(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		c.Connect.Routes, c.Connect.AllowedTargets = routesBroker, nil
		c.Connect.Upstream = broker.upstream(c.Connect.Upstream)
	})
	if _, _, status := sf.connect(t, ""); status != 200 {
		t.Fatalf("connect: %d", status)
	}
	broker.srv.Listener.Close()
	broker.dropTunnels()
	for i := 0; i < 4; i++ {
		if _, _, status := sf.connect(t, ""); status == 200 {
			t.Fatal("connected to a closed broker")
		}
	}
	if n := len(sink.lines(t, "upstream_unreachable")); n != 1 {
		t.Fatalf("%d unreachable events for one outage", n)
	}
	var w upstreamWatch
	w.dialed(newRelayLog(), "broker:443", io.EOF)
	w.dialed(newRelayLog(), "broker:443", io.EOF)
	w.dialed(newRelayLog(), "broker:443", nil)
	w.dialed(newRelayLog(), "broker:443", nil)
	if n := len(sink.lines(t, "upstream_restored")); n != 1 {
		t.Fatalf("%d restored events", n)
	}
}

func TestReadCause(t *testing.T) {
	for _, tc := range []struct {
		upstream bool
		err      error
		want     string
	}{
		{true, io.EOF, endUpstreamClosed}, {false, io.EOF, endClientClosed},
		{true, io.ErrUnexpectedEOF, endUpstreamReset}, {false, io.ErrUnexpectedEOF, endClientReset},
		{true, nil, ""},
	} {
		if got := readCause(tc.upstream, tc.err); got != tc.want {
			t.Errorf("%v %v: %q, want %q", tc.upstream, tc.err, got, tc.want)
		}
	}
	var e ending
	e.set(endUpstreamReset)
	e.set(endClientClosed)
	if e.get() != endUpstreamReset {
		t.Fatal("a later cause replaced the first")
	}
}

// TestMain keeps relay logs out of test output; captureLog redirects them.
func TestMain(m *testing.M) {
	logOutput = io.Discard
	m.Run()
}

// A PostgreSQL session's end is logged the same way.
func TestPostgresSessionEndIsLogged(t *testing.T) {
	sink := captureLog(t)
	backend := newCatalogBackend(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		upstream := c.Connect.Upstream
		upstream.Address = backend.raw.Addr().String()
		c.PostgresListener = &PostgresListenerConfig{Listen: freeAddress(t), Upstream: upstream, Routes: routesBroker, User: "workload", Placeholder: "placeholder"}
	})
	backend.serve(sf.f.cert)
	c, _ := openRouted(t, sf, sslRequestCode, "appdb")
	<-backend.databases
	c.Close()
	waitUntil(t, "the session's end", func() bool { return len(sink.lines(t, "session_closed")) == 1 })
	if line := sink.lines(t, "session_closed")[0]; line["protocol"] != "postgres" || line["reason"] != endClientClosed || line["target"] != "appdb" {
		t.Fatalf("postgres end: %v", line)
	}
}

// At its limit the relay refuses new connections, leaves open ones alone, and
// logs the refusals once per window with their count.
func TestRefusalsAtTheLimitAreLoggedAndSpareOpenSessions(t *testing.T) {
	sink := captureLog(t)
	f := newRelayFixture(t)
	f.c.MaxConnections = 3
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, "127.0.0.1:25443"), Database: "d", User: "workload", Placeholder: "p"}
	f.start(t)
	for i := 0; i < 3; i++ {
		f.dial(t, f.c.Postgres.Listen) // held open until the test ends
	}
	tc, _ := clientTLS(f.c.TLSCertFile, "127.0.0.1")
	for i := 0; i < 2; i++ {
		if extra, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.c.Postgres.Listen, tc); e == nil {
			extra.Close()
			t.Fatal("a connection past the limit was admitted")
		}
	}
	waitUntil(t, "the refusal event", func() bool { return len(sink.lines(t, "connections_refused")) == 1 })
	event := sink.lines(t, "connections_refused")[0]
	if event["refused"].(float64) < 2 || event["limit"] != "3" || event["level"] != "WARN" {
		t.Fatalf("refusal event: %v", event)
	}
	if n := len(sink.lines(t, "session_closed")); n != 0 {
		t.Fatalf("%d open sessions ended at the limit", n)
	}
}

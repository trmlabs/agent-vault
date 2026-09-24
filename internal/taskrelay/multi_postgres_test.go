package taskrelay

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestPostgresBindingsValidation(t *testing.T) {
	f := newRelayFixture(t)
	binding := PostgresConfig{Listen: "127.0.0.1:15443", Upstream: f.upstream(t, "127.0.0.1:25443"), Database: "first", User: "workload", Placeholder: "public-placeholder"}
	cases := []struct {
		name   string
		change func(*FixedConfig)
		valid  bool
	}{
		{"legacy", func(c *FixedConfig) { c.Postgres = &binding }, true},
		{"five", func(c *FixedConfig) {
			for i := 0; i < 5; i++ {
				p := binding
				p.Listen = fmt.Sprintf("127.0.0.1:%d", 15443+i)
				c.PostgresBindings = append(c.PostgresBindings, p)
			}
		}, true},
		{"mixed", func(c *FixedConfig) { c.Postgres = &binding; c.PostgresBindings = []PostgresConfig{binding} }, false},
		{"too-many", func(c *FixedConfig) {
			for i := 0; i < 9; i++ {
				p := binding
				p.Listen = fmt.Sprintf("127.0.0.1:%d", 15443+i)
				c.PostgresBindings = append(c.PostgresBindings, p)
			}
		}, false},
		{"duplicate-listener", func(c *FixedConfig) { c.PostgresBindings = []PostgresConfig{binding, binding} }, false},
		{"other-protocol-listener", func(c *FixedConfig) {
			c.PostgresBindings = []PostgresConfig{binding}
			c.Connect = &ConnectConfig{Listen: binding.Listen, Upstream: binding.Upstream, AllowedTargets: []string{"approved.test:443"}}
		}, false},
		{"bad-authority", func(c *FixedConfig) { p := binding; p.Database = "bad/name"; c.PostgresBindings = []PostgresConfig{p} }, false},
		{"empty", func(c *FixedConfig) {}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := f.c
			tt.change(&c)
			if (c.Validate(time.Now()) == nil) != tt.valid {
				t.Fatal("unexpected validation decision")
			}
		})
	}
}

type bindingBackend struct {
	listener      net.Listener
	arrivals      atomic.Int32
	cancellations chan []byte
}

func newBindingBackend(t *testing.T, f *relayFixture, name string) *bindingBackend {
	t.Helper()
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}})
	if e != nil {
		t.Fatal(e)
	}
	b := &bindingBackend{listener: l, cancellations: make(chan []byte, 8)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				packet, e := readStartupPacket(c)
				if e != nil {
					return
				}
				if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
					b.cancellations <- packet
					return
				}
				b.arrivals.Add(1)
				var startup pgproto3.StartupMessage
				if startup.Decode(packet[4:]) != nil || startup.Parameters["database"] != name {
					return
				}
				_, _ = c.Write(encodePGFrame('R', []byte{0, 0, 0, 3}))
				typ, _, e := readPGFrame(c, 32768)
				if e != nil || typ != 'p' {
					return
				}
				_, _ = c.Write(encodePGFrame('R', []byte{0, 0, 0, 0}))
				_, _ = c.Write(encodePGFrame('K', []byte{0, 0, 0, 7, 0, 0, 0, 9}))
				_, _ = c.Write(encodePGFrame('Z', []byte{'I'}))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return b
}
func openBinding(t *testing.T, f *relayFixture, p PostgresConfig) (net.Conn, []byte) {
	t.Helper()
	c := f.dial(t, p.Listen)
	packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": p.User, "database": p.Database}}).Encode(nil)
	_, _ = c.Write(packet)
	typ, _, e := readPGFrame(c, 1024)
	if e != nil || typ != 'R' {
		t.Fatal("missing placeholder request")
	}
	_, _ = c.Write(encodePGFrame('p', []byte(p.Placeholder+"\x00")))
	var key []byte
	for {
		typ, body, e := readPGFrame(c, 8192)
		if e != nil {
			t.Fatal(e)
		}
		if typ == 'K' {
			key = body
		}
		if typ == 'Z' {
			break
		}
	}
	if len(key) != 8 {
		t.Fatal("missing cancellation key")
	}
	return c, key
}
func cancelBinding(t *testing.T, f *relayFixture, p PostgresConfig, key []byte) {
	t.Helper()
	c := f.dial(t, p.Listen)
	packet := binary.BigEndian.AppendUint32(nil, 16)
	packet = binary.BigEndian.AppendUint32(packet, cancelCode)
	packet = append(packet, key...)
	_, _ = c.Write(packet)
	_, _ = io.Copy(io.Discard, c)
	_ = c.Close()
}
func TestFivePostgresBindingsRoutingCancellationAndWithdrawal(t *testing.T) {
	f := newRelayFixture(t)
	var backends []*bindingBackend
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("database-%d", i)
		b := newBindingBackend(t, f, name)
		backends = append(backends, b)
		f.c.PostgresBindings = append(f.c.PostgresBindings, PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, b.listener.Addr().String()), Database: name, User: "workload", Placeholder: "public-placeholder"})
	}
	f.start(t)
	var clients []net.Conn
	var keys [][]byte
	for _, p := range f.c.PostgresBindings {
		c, key := openBinding(t, f, p)
		clients = append(clients, c)
		keys = append(keys, key)
	}
	// A valid key from another binding must never be routed through this listener.
	cancelBinding(t, f, f.c.PostgresBindings[1], keys[0])
	for _, b := range backends {
		select {
		case <-b.cancellations:
			t.Fatal("cross-binding cancel reached upstream")
		default:
		}
	}
	cancelBinding(t, f, f.c.PostgresBindings[0], keys[0])
	select {
	case <-backends[0].cancellations:
	case <-time.After(time.Second):
		t.Fatal("same-binding cancellation failed")
	}
	// Wrong database on an otherwise permitted listener fails before upstream admission.
	wrong := f.dial(t, f.c.PostgresBindings[0].Listen)
	packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "database-1"}}).Encode(nil)
	_, _ = wrong.Write(packet)
	_, _ = io.Copy(io.Discard, wrong)
	_ = wrong.Close()
	if backends[0].arrivals.Load() != 1 {
		t.Fatal("wrong binding reached upstream")
	}
	for i, c := range clients {
		_, _ = c.Write([]byte{'x'})
		var b [1]byte
		if _, e := io.ReadFull(c, b[:]); e != nil || b[0] != 'x' {
			t.Fatalf("binding %d did not remain usable", i)
		}
	}
	f.state.Store(1)
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("pair replacement did not stop task")
	}
	for i, c := range clients {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, e := c.Read(b[:])
		if e == nil {
			t.Fatalf("binding %d remains open", i)
		}
		if n, ok := e.(net.Error); ok && n.Timeout() {
			t.Fatal("withdrawal did not close established connection")
		}
	}
}

func TestPostgresBindingsShareConnectionLimit(t *testing.T) {
	f := newRelayFixture(t)
	for i := 0; i < 5; i++ {
		f.c.PostgresBindings = append(f.c.PostgresBindings, PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, "127.0.0.1:25443"), Database: fmt.Sprintf("database-%d", i), User: "workload", Placeholder: "public-placeholder"})
	}
	f.start(t)
	clients := make([]net.Conn, 0, maxConnections)
	for i := 0; i < maxConnections; i++ {
		p := f.c.PostgresBindings[i%5]
		c := f.dial(t, p.Listen)
		packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": p.User, "database": p.Database}}).Encode(nil)
		_, _ = c.Write(packet)
		typ, _, e := readPGFrame(c, 1024)
		if e != nil || typ != 'R' {
			t.Fatal("permitted capacity did not reach placeholder prompt")
		}
		clients = append(clients, c)
	}
	tc, e := clientTLS(f.c.TLSCertFile, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if extra, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.c.PostgresBindings[4].Listen, tc); e == nil {
		_ = extra.Close()
		t.Fatal("extra binding multiplied task connection capacity")
	}
	// Releasing a slot restores capacity across a different binding.
	_ = clients[0].Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", f.c.PostgresBindings[4].Listen, tc)
		if e == nil {
			clients[0] = c
			// Withdrawal is independent of listener capacity, including at the cap.
			f.state.Store(1)
			select {
			case <-f.done:
			case <-time.After(5 * time.Second):
				t.Fatal("saturated task did not stop on withdrawal")
			}
			for _, client := range clients {
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				var value [1]byte
				_, err := client.Read(value[:])
				_ = client.Close()
				if err == nil {
					t.Fatal("saturated connection stayed open after withdrawal")
				}
				if n, ok := err.(net.Error); ok && n.Timeout() {
					t.Fatal("saturated connection did not close")
				}
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("shared connection capacity did not recover")
}

func TestPostgresBindingBindFailureClosesTask(t *testing.T) {
	f := newRelayFixture(t)
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	f.c.PostgresBindings = []PostgresConfig{
		{Listen: freeAddress(t), Upstream: f.upstream(t, "127.0.0.1:25443"), Database: "first", User: "workload", Placeholder: "public-placeholder"},
		{Listen: occupied.Addr().String(), Upstream: f.upstream(t, "127.0.0.1:25443"), Database: "second", User: "workload", Placeholder: "public-placeholder"},
	}
	if e := Run(t.Context(), f.c); e == nil {
		t.Fatal("partial binding startup accepted")
	}
	if c, e := net.DialTimeout("tcp", f.c.PostgresBindings[0].Listen, time.Second); e == nil {
		_ = c.Close()
		t.Fatal("earlier listener remained open after task startup failed")
	}
}

package taskrelay

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// A sidecar with a session file sends "GHSESS1 <token>" on the broker-side
// stream ahead of the startup it authors; without one it sends the startup
// alone. The worker never supplies either.
func TestSelfModePostgresCarriesTheRunnerSession(t *testing.T) {
	const token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.c2ln"
	for name, session := range map[string]string{"with a session": token, "without one": ""} {
		t.Run(name, func(t *testing.T) {
			f := newRelayFixture(t)
			l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			type seen struct {
				line    string
				startup map[string]string
			}
			got := make(chan seen, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(c)
				var s seen
				if head, _ := r.Peek(8); string(head) == "GHSESS1 " {
					s.line, _ = r.ReadString('\n')
				}
				packet, e := readStartupPacket(r)
				if e != nil {
					return
				}
				var m pgproto3.StartupMessage
				if m.Decode(packet[4:]) == nil {
					s.startup = m.Parameters
				}
				got <- s
			}()
			up := f.upstream(t, l.Addr().String())
			if session != "" {
				up.SessionFile = filepath.Join(t.TempDir(), "token")
				writeTestFile(t, up.SessionFile, []byte(session+"\n"))
			}
			listen := freeAddress(t)
			c := FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(t.TempDir(), "audit.jsonl"), Self: true,
				PostgresBindings: []PostgresConfig{{Listen: listen, Upstream: up, Database: "core", User: "workload", Placeholder: "gatehouse-relay-placeholder"}}}
			if e := c.Validate(time.Now()); e != nil {
				t.Fatalf("config refused: %v", e)
			}
			go func() { _ = Run(t.Context(), c) }()
			var conn net.Conn
			for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				if conn, e = net.Dial("tcp", listen); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("relay never listened")
				}
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "core"}}).Encode(nil)
			_, _ = conn.Write(b)
			typ, body, e := readPGFrame(conn, 1024)
			if e != nil || typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
				t.Fatal("startup refused")
			}
			_, _ = conn.Write(encodePGFrame('p', []byte("gatehouse-relay-placeholder\x00")))
			select {
			case s := <-got:
				want := ""
				if session != "" {
					want = "GHSESS1 " + session + "\n"
				}
				if s.line != want || s.startup["database"] != "core" {
					t.Fatalf("broker saw line %q startup %v, want line %q", s.line, s.startup, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("nothing reached the broker")
			}
		})
	}
}

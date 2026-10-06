package taskrelay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// catalogBackend is one broker PostgreSQL listener for every database: it
// reads the shared proxy's attestation line, then the startup, and records
// which database each session asked for.
type catalogBackend struct {
	raw           net.Listener
	arrivals      atomic.Int32
	databases     chan string
	cancellations chan []byte
}

func newCatalogBackend(t *testing.T) *catalogBackend {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &catalogBackend{raw: l, databases: make(chan string, 16), cancellations: make(chan []byte, 4)}
}

// serve starts answering once the fixture's certificate exists.
func (b *catalogBackend) serve(cert tls.Certificate) {
	l := tls.NewListener(b.raw, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				in := bufio.NewReader(c)
				if head, e := in.Peek(8); e == nil && string(head) == "GHATTS1 " {
					if _, e := in.ReadString('\n'); e != nil {
						return
					}
				}
				packet, e := readStartupPacket(in)
				if e != nil {
					return
				}
				if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
					b.cancellations <- packet
					return
				}
				b.arrivals.Add(1)
				var startup pgproto3.StartupMessage
				if startup.Decode(packet[4:]) != nil {
					return
				}
				b.databases <- startup.Parameters["database"]
				_, _ = c.Write(encodePGFrame('R', []byte{0, 0, 0, 3}))
				if typ, _, e := readPGFrame(in, 32768); e != nil || typ != 'p' {
					return
				}
				_, _ = c.Write(encodePGFrame('R', []byte{0, 0, 0, 0}))
				_, _ = c.Write(encodePGFrame('K', []byte{0, 0, 0, 7, 0, 0, 0, 9}))
				_, _ = c.Write(encodePGFrame('Z', []byte{'I'}))
				for {
					typ, body, e := readPGFrame(in, 8192)
					if e != nil {
						return
					}
					_, _ = c.Write(encodePGFrame(typ, body))
				}
			}()
		}
	}()
}

func catalogNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("catalog-db-%05d", i)
	}
	return names
}

// openRouted runs one client through the single port: an optional
// SSLRequest or GSSENCRequest (declined in plaintext), the startup naming
// database, the placeholder, then the broker's ready frames.
func openRouted(t *testing.T, sf *sharedFixture, first uint32, database string) (net.Conn, []byte) {
	t.Helper()
	c := sf.dial(t, sf.f.c.PostgresListener.Listen)
	if first != 0 {
		_, _ = c.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, first))
		answer := make([]byte, 1)
		if _, e := io.ReadFull(c, answer); e != nil || answer[0] != 'N' {
			t.Fatalf("request %d answered %q %v", first, answer, e)
		}
	}
	packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"user": "workload", "database": database}}).Encode(nil)
	_, _ = c.Write(packet)
	if typ, _, e := readPGFrame(c, 1024); e != nil || typ != 'R' {
		t.Fatalf("%s: missing placeholder request: %v", database, e)
	}
	_, _ = c.Write(encodePGFrame('p', []byte("placeholder\x00")))
	var key []byte
	for {
		typ, body, e := readPGFrame(c, 8192)
		if e != nil {
			t.Fatalf("%s: %v", database, e)
		}
		if typ == 'K' {
			key = body
		}
		if typ == 'Z' {
			return c, key
		}
	}
}

// One port serves a catalog of thousands: each name in it reaches the broker
// as that database, whether the client asked for TLS or GSS encryption first
// or not; a name outside it, or none, is refused with the catalog words and
// never reaches the broker; and a cancellation on the port reaches the
// broker socket that session used.
func TestSharedPostgresListenerRoutesByCatalog(t *testing.T) {
	names := catalogNames(5000)
	backend := newCatalogBackend(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		upstream := c.Connect.Upstream
		upstream.Address = backend.raw.Addr().String()
		c.PostgresListener = &PostgresListenerConfig{Listen: freeAddress(t), Upstream: upstream, Databases: names, User: "workload", Placeholder: "placeholder"}
	})
	backend.serve(sf.f.cert)
	var clients []net.Conn
	var keys [][]byte
	for i, route := range []struct {
		first    uint32
		database string
	}{{sslRequestCode, names[0]}, {gssRequestCode, names[2500]}, {0, names[4999]}} {
		c, key := openRouted(t, sf, route.first, route.database)
		if got := <-backend.databases; got != route.database {
			t.Fatalf("route %d reached the broker as %q, want %q", i, got, route.database)
		}
		clients, keys = append(clients, c), append(keys, key)
	}
	for i, c := range clients {
		_, _ = c.Write(encodePGFrame('d', []byte{'x'}))
		if typ, b, e := readPGFrame(c, 16); e != nil || typ != 'd' || string(b) != "x" {
			t.Fatalf("route %d did not stay usable: %v", i, e)
		}
	}
	for _, database := range []string{"catalog-db-05000", "", "appdb"} {
		c := sf.dial(t, sf.f.c.PostgresListener.Listen)
		parameters := map[string]string{"user": "workload"}
		if database != "" {
			parameters["database"] = database
		}
		packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
		_, _ = c.Write(packet)
		typ, body, e := readPGFrame(c, 8192)
		if e != nil || typ != 'E' || sqlState(body) != "3D000" || errorField(body, 'M') != refusalsByReason["no_database"].message {
			t.Fatalf("%q: not refused with the catalog words: %c %q %v", database, typ, body, e)
		}
	}
	if n := backend.arrivals.Load(); n != 3 {
		t.Fatalf("%d sessions reached the broker, want 3", n)
	}
	c := sf.dial(t, sf.f.c.PostgresListener.Listen)
	_, _ = c.Write(append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 16), cancelCode), keys[1]...))
	_, _ = io.Copy(io.Discard, c)
	select {
	case packet := <-backend.cancellations:
		if !bytes.Equal(packet[8:], []byte{0, 0, 0, 7, 0, 0, 0, 9}) {
			t.Fatalf("cancellation carried %x, not the broker's key", packet[8:])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation on the single port did not reach the broker")
	}
	audit, _ := os.ReadFile(sf.f.c.AuditFile)
	if bytes.Count(audit, []byte(`denied:no-database`)) != 3 {
		t.Fatalf("refusals not audited: %s", audit)
	}
}

// The single port is shared mode only, needs at least one database, and
// refuses a bad or repeated name, a listen address another listener uses,
// and a session file. Its size is not capped by count.
func TestPostgresListenerValidation(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:3128", Upstream: f.upstream(t, "broker.internal:443"), AllowedTargets: []string{"api.example.com:443"}}
		c.PostgresListener = &PostgresListenerConfig{Listen: "0.0.0.0:15432", Upstream: f.upstream(t, "broker.internal:5432"),
			Databases: catalogNames(20000), User: "workload", Placeholder: "placeholder"}
		return c
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("20,000 routes refused: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"not shared":      func(c *FixedConfig) { c.Shared = nil },
		"no databases":    func(c *FixedConfig) { c.PostgresListener.Databases = nil },
		"repeated name":   func(c *FixedConfig) { c.PostgresListener.Databases = []string{"a", "b", "a"} },
		"bad name":        func(c *FixedConfig) { c.PostgresListener.Databases = []string{"a", "b c"} },
		"empty name":      func(c *FixedConfig) { c.PostgresListener.Databases = []string{""} },
		"no user":         func(c *FixedConfig) { c.PostgresListener.User = "" },
		"no placeholder":  func(c *FixedConfig) { c.PostgresListener.Placeholder = "" },
		"reused address":  func(c *FixedConfig) { c.PostgresListener.Listen = c.Connect.Listen },
		"session file":    func(c *FixedConfig) { c.PostgresListener.Upstream.SessionFile = "/var/run/session" },
		"no upstream CA":  func(c *FixedConfig) { c.PostgresListener.Upstream.CAFile = "" },
		"admin collision": func(c *FixedConfig) { c.AdminListen = c.PostgresListener.Listen },
	} {
		c := base()
		listener := *c.PostgresListener
		c.PostgresListener = &listener
		mutate(&c)
		if e := c.Validate(time.Now()); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A rendered config with the whole catalog loads: the file bound is sized
	// for the route table.
	c := base()
	c.TLSCertFile, c.TLSKeyFile, c.Deadline = "", "", time.Time{}
	c.PostgresListener.Databases = make([]string, 20000)
	for i := range c.PostgresListener.Databases {
		c.PostgresListener.Databases[i] = fmt.Sprintf("%s-%05d", strings.Repeat("d", 200), i)
	}
	b, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "relay.json")
	writeTestFile(t, path, b)
	if _, e := LoadConfig(path); e != nil {
		t.Fatalf("a %d-byte config with 20,000 routes: %v", len(b), e)
	}
}

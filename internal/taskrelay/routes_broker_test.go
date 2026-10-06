package taskrelay

import (
	"bufio"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// With routes "broker", CONNECT forwards any well-formed host:443 to the
// broker and the broker's refusal reaches the client as a refusal. A
// malformed target, an IP literal or another port is refused before the
// broker hears of it.
func TestConnectRoutesBroker(t *testing.T) {
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		c.Connect.Routes, c.Connect.AllowedTargets = routesBroker, nil
	})
	var hosts []string
	connect := func(target string) int {
		c := sf.dial(t, sf.f.c.Connect.Listen)
		io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		response, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
		if e != nil {
			return 0
		}
		response.Body.Close()
		return response.StatusCode
	}
	for _, target := range []string{"api.github.com:443", "litellm.internal.trmlabs.com:443", "a1.b2:443"} {
		if status := connect(target); status != 200 {
			t.Fatalf("%s: %d", target, status)
		}
		select {
		case <-sf.attested:
			hosts = append(hosts, target)
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not reach the broker", target)
		}
	}
	for _, target := range []string{"1.2.3.4:443", "[::1]:443", "api.github.com:80", "api.github.com", "API.github.com:443", "localhost:443",
		"github..com:443", "github-.com:443", "github.com.:443", "10.0.0.1.nip:443x", "github.com:0443", "169.254.169.254:443", "user@github.com:443"} {
		// 403 from the relay, or 400 where the HTTP parser refuses it first.
		if status := connect(target); status != 403 && status != 400 {
			t.Errorf("%s: %d, want a refusal", target, status)
		}
	}
	select {
	case got := <-sf.attested:
		t.Fatalf("a refused target reached the broker: %q", got)
	default:
	}
	if len(hosts) != 3 {
		t.Fatalf("forwarded %v", hosts)
	}
}

// The broker's 403 for a target outside the catalog reaches the client as a
// 403, not as an outage.
func TestConnectBrokerRefusalIsARefusal(t *testing.T) {
	broker := newActivityBroker(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		c.Connect.Routes, c.Connect.AllowedTargets = routesBroker, nil
		c.Connect.Upstream = broker.upstream(c.Connect.Upstream)
	})
	broker.refuseHosts.Store(true)
	c := sf.dial(t, sf.f.c.Connect.Listen)
	io.WriteString(c, "CONNECT unlisted.example.com:443 HTTP/1.1\r\nHost: unlisted.example.com:443\r\n\r\n")
	response, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 403 || strings.Contains(string(body), "catalog") {
		t.Fatalf("broker refusal: %d %q", response.StatusCode, body)
	}
}

// With routes "broker", the single PostgreSQL port forwards any well-formed
// database name; the broker refuses one not in the pool's catalog, and the
// client gets the same 3D000 words a local refusal gives. A missing or
// malformed name is refused before the broker is dialed.
func TestPostgresRoutesBroker(t *testing.T) {
	backend := newCatalogBackend(t)
	sf := startSharedWith(t, false, true, func(c *FixedConfig) {
		upstream := c.Connect.Upstream
		upstream.Address = backend.raw.Addr().String()
		c.PostgresListener = &PostgresListenerConfig{Listen: freeAddress(t), Upstream: upstream, Routes: routesBroker, User: "workload", Placeholder: "placeholder"}
	})
	backend.refuse = func(database string) bool { return strings.HasPrefix(database, "unknown") }
	backend.serve(sf.f.cert)
	c, _ := openRouted(t, sf, sslRequestCode, "anything-in-the-catalog")
	defer c.Close()
	if got := <-backend.databases; got != "anything-in-the-catalog" {
		t.Fatalf("reached the broker as %q", got)
	}
	refusal := func(database string, omit bool) (string, string) {
		conn := sf.dial(t, sf.f.c.PostgresListener.Listen)
		defer conn.Close()
		parameters := map[string]string{"user": "workload", "database": database}
		if omit {
			delete(parameters, "database")
		}
		packet, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
		conn.Write(packet)
		typ, body, e := readPGFrame(conn, 8192)
		if e == nil && typ == 'R' && binary.BigEndian.Uint32(body) == 3 {
			conn.Write(encodePGFrame('p', []byte("placeholder\x00")))
			typ, body, e = readPGFrame(conn, 8192)
		}
		if e != nil || typ != 'E' {
			t.Fatalf("%q: no refusal: %c %v", database, typ, e)
		}
		return sqlState(body), errorField(body, 'M')
	}
	before := backend.arrivals.Load()
	localCode, localWords := refusal("", true)
	for _, bad := range []string{strings.Repeat("d", 64), "a b", "tab\tname"} {
		if code, words := refusal(bad, false); code != "3D000" || words != localWords {
			t.Errorf("%q: %s %q", bad, code, words)
		}
	}
	if n := backend.arrivals.Load(); n != before {
		t.Fatalf("a malformed name reached the broker (%d arrivals)", n-before)
	}
	brokerCode, brokerWords := refusal("unknown-database", false)
	if <-backend.databases != "unknown-database" {
		t.Fatal("an unknown name did not reach the broker")
	}
	if localCode != "3D000" || brokerCode != localCode || brokerWords != localWords {
		t.Fatalf("local %s %q, broker %s %q", localCode, localWords, brokerCode, brokerWords)
	}
}

// Routes "broker" is explicit and exclusive: with a list it is refused, an
// unknown value is refused, and with neither a list nor the flag the config is
// refused, so dropping a list never opens a listener. Outside shared mode it
// does not exist.
func TestRoutesBrokerValidation(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:3128", Upstream: f.upstream(t, "broker.internal:443"), Routes: routesBroker}
		c.PostgresListener = &PostgresListenerConfig{Listen: "0.0.0.0:15432", Upstream: f.upstream(t, "broker.internal:5432"), Routes: routesBroker,
			User: "workload", Placeholder: "placeholder"}
		return c
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("broker routes refused: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"CONNECT flag and list":    func(c *FixedConfig) { c.Connect.AllowedTargets = []string{"api.github.com:443"} },
		"CONNECT neither":          func(c *FixedConfig) { c.Connect.Routes = "" },
		"CONNECT other value":      func(c *FixedConfig) { c.Connect.Routes = "any" },
		"PostgreSQL flag and list": func(c *FixedConfig) { c.PostgresListener.Databases = []string{"appdb"} },
		"PostgreSQL neither":       func(c *FixedConfig) { c.PostgresListener.Routes = "" },
		"PostgreSQL other value":   func(c *FixedConfig) { c.PostgresListener.Routes = "Broker" },
	} {
		c := base()
		connect, listener := *c.Connect, *c.PostgresListener
		c.Connect, c.PostgresListener = &connect, &listener
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	paired := f.c
	paired.Connect = &ConnectConfig{Listen: "127.0.0.1:3128", Upstream: f.upstream(t, "broker.internal:443"), Routes: routesBroker,
		AllowedTargets: []string{"api.github.com:443"}}
	if paired.Validate(time.Now()) == nil {
		t.Error("broker routes outside shared mode accepted")
	}
}

func TestBrokerRouteShapes(t *testing.T) {
	for target, want := range map[string]bool{
		"api.github.com:443": true, "a.b:443": true, "x1.y2.z3:443": true, "xn--bcher-kva.example:443": true,
		"1.2.3.4:443": false, "a.123:443": false, "[2001:db8::1]:443": false, "a.b:8443": false, "a.b": false, "a:443": false,
		strings.Repeat("a", 64) + ".com:443": false, "-a.com:443": false, "a_b.com:443": false, "a.b:443\n": false,
	} {
		if got := brokerRouteTarget(target); got != want {
			t.Errorf("target %q: %v", target, got)
		}
	}
	for name, want := range map[string]bool{
		"appdb": true, "b2b-core.v2": true, strings.Repeat("d", 63): true, "%_$": true,
		"": false, strings.Repeat("d", 64): false, "a b": false, "a\x00b": false, "é": false,
	} {
		if got := brokerRouteDatabase(name); got != want {
			t.Errorf("database %q: %v", name, got)
		}
	}
}

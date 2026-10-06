package taskrelay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

const (
	sandboxDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	otherDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// sandboxPod is an agent-sandbox Pod: owned by its Sandbox, running one
// approved image, at ip.
func sandboxPod(name, uid, ip string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "agent-sandboxes", "uid": uid, "resourceVersion": "5",
			"ownerReferences": []any{map[string]any{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox", "uid": "sandbox-" + uid, "controller": true, "blockOwnerDeletion": true}}},
		"spec": map[string]any{},
		"status": map[string]any{"phase": "Running", "podIP": ip, "startTime": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
			"containerStatuses": []any{map[string]any{"imageID": "registry.example/agent@" + sandboxDigest}}},
	}
}

func sharedConfig() *SharedConfig {
	return &SharedConfig{Profiles: map[string]string{"agent-sandboxes": "agent-sandbox-developers"}, OwnerKind: "Sandbox", OwnerAPIVersion: "agents.x-k8s.io/v1beta1",
		ImageDigests: []string{sandboxDigest}, MaxPodSeconds: 3600}
}

// fakeAPI serves a namespace's Pods: one list, then a watch that streams the
// events the test sends.
type fakeAPI struct {
	srv    *httptest.Server
	mu     sync.Mutex
	pods   []map[string]any
	events chan string
	lists  int
}

func newFakeAPI(t *testing.T, f *relayFixture, pods ...map[string]any) *fakeAPI {
	t.Helper()
	api := &fakeAPI{pods: pods, events: make(chan string, 16)}
	api.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/agent-sandboxes/pods" || r.Header.Get("Authorization") != "Bearer synthetic-reviewer" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Query().Get("watch") != "1" {
			api.mu.Lock()
			api.lists++
			items := append([]map[string]any(nil), api.pods...)
			api.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "10"}, "items": items})
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case e := <-api.events:
				io.WriteString(w, e+"\n")
				w.(http.Flusher).Flush()
			case <-time.After(5 * time.Second):
				return
			}
		}
	}))
	api.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	api.srv.StartTLS()
	t.Cleanup(api.srv.Close)
	return api
}

func (api *fakeAPI) send(t *testing.T, kind string, pod map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"type": kind, "object": pod})
	api.events <- string(b)
}

type sharedFixture struct {
	f         *relayFixture
	api       *fakeAPI
	attested  chan string
	plaintext bool
}

// startShared runs the relay in shared mode in front of a broker that
// records each CONNECT's attestation and echoes the tunnel.
func startShared(t *testing.T, postgres bool) *sharedFixture {
	t.Helper()
	return startSharedWith(t, postgres, false)
}

// startSharedWith can run the listeners in plaintext, with no certificate.
func startSharedWith(t *testing.T, postgres, plaintext bool, options ...func(*FixedConfig)) *sharedFixture {
	t.Helper()
	return startSharedPods(t, postgres, plaintext, []map[string]any{sandboxPod("sandbox-a", "pod-a", "127.0.0.1")}, options...)
}

// startSharedPods is startSharedWith with the agent Pods the API lists at
// start.
func startSharedPods(t *testing.T, postgres, plaintext bool, pods []map[string]any, options ...func(*FixedConfig)) *sharedFixture {
	t.Helper()
	f := newRelayFixture(t)
	sf := &sharedFixture{f: f, api: newFakeAPI(t, f, pods...), attested: make(chan string, 8)}
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sf.attested <- r.Header.Get("Gatehouse-Attestation")
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	}))
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	broker.StartTLS()
	t.Cleanup(broker.Close)
	f.c.Sandbox = SandboxConfig{}
	f.c.Kubernetes.APIURL = sf.api.srv.URL
	f.c.Shared = sharedConfig()
	f.c.Deadline = time.Now().Add(time.Hour)
	f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
	if postgres {
		f.c.PostgresBindings = []PostgresConfig{{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()),
			Database: "appdb", User: "workload", Placeholder: "placeholder"}}
	}
	if plaintext {
		sf.plaintext = true
		f.c.TLSCertFile, f.c.TLSKeyFile = "", ""
		f.c.Deadline = time.Time{}
		path := filepath.Join(t.TempDir(), "relay.json")
		b, _ := json.Marshal(f.c)
		writeTestFile(t, path, b)
		loaded, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("a shared config with no deadline and no certificate: %v", err)
		}
		f.c = loaded
	}
	for _, option := range options {
		option(&f.c)
	}
	f.start(t)
	return sf
}

// dial connects to a listener, in TLS unless the fixture is plaintext.
func (sf *sharedFixture) dial(t *testing.T, address string) net.Conn {
	t.Helper()
	if !sf.plaintext {
		return sf.f.dial(t, address)
	}
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(4 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// connect opens a tunnel through the shared proxy and returns its reader and
// the status, with extra CONNECT header lines.
func (sf *sharedFixture) connect(t *testing.T, extra string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	c := sf.dial(t, sf.f.c.Connect.Listen)
	io.WriteString(c, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n"+extra+"\r\n")
	b := bufio.NewReader(c)
	response, e := http.ReadResponse(b, &http.Request{Method: "CONNECT"})
	if e != nil {
		return c, b, 0
	}
	defer response.Body.Close()
	return c, b, response.StatusCode
}

func tunnelCloses(t *testing.T, c net.Conn, b *bufio.Reader) bool {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, e := b.ReadByte()
	// A read that times out found the tunnel still open.
	var timeout net.Error
	return e != nil && (!errors.As(e, &timeout) || !timeout.Timeout())
}

// The shared proxy attests the agent Pod at the connection's source, and
// drops the tunnel once that Pod stops qualifying.
func TestSharedProxyAttestsThenDropsTheAgent(t *testing.T) {
	sf := startShared(t, false)
	c, b, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(<-sf.attested)
	var a workloadidentity.Attestation
	if json.Unmarshal(raw, &a) != nil || a.PodUID != "pod-a" || a.Profile != "agent-sandbox-developers" || a.OwnerUID != "sandbox-pod-a" ||
		a.OwnerKind != "Sandbox" || a.Namespace != "agent-sandboxes" || a.NotAfter <= time.Now().Unix() {
		t.Fatalf("attestation %s", raw)
	}
	io.WriteString(c, "hello")
	echo := make([]byte, 5)
	if _, e := io.ReadFull(b, echo); e != nil || string(echo) != "hello" {
		t.Fatal("tunnel did not relay")
	}
	// The Sandbox is deleted: its Pod starts terminating.
	gone := sandboxPod("sandbox-a", "pod-a", "127.0.0.1")
	gone["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	sf.api.send(t, "MODIFIED", gone)
	if !tunnelCloses(t, c, b) {
		t.Fatal("a deleted agent's tunnel stayed open")
	}
	if _, _, status := sf.connect(t, ""); status == 200 {
		t.Fatal("a deleted agent was admitted")
	}
}

// The recheck compares the controller too: the same Pod under a replaced
// Sandbox is a different agent.
func TestSharedProxyDropsTheAgentWhenItsSandboxChanges(t *testing.T) {
	sf := startShared(t, false)
	c, b, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	<-sf.attested
	moved := sandboxPod("sandbox-a", "pod-a", "127.0.0.1")
	moved["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "sandbox-replacement"
	sf.api.send(t, "MODIFIED", moved)
	if !tunnelCloses(t, c, b) {
		t.Fatal("a tunnel survived its Sandbox UID changing")
	}
}

// A client cannot speak for the proxy: an attestation or PROXY header it
// sends is refused before anything reaches the broker.
func TestSharedProxyRefusesClientAttestations(t *testing.T) {
	sf := startShared(t, true)
	for _, extra := range []string{"Gatehouse-Attestation: forged\r\n", "Gatehouse-Session: a.b.c\r\n", "Forwarded: for=10.0.0.9\r\n"} {
		if _, _, status := sf.connect(t, extra); status != 403 {
			t.Errorf("CONNECT with %q: %d", extra, status)
		}
	}
	for _, start := range []string{"GHATTS1 forged\n", "GHSESS1 a.b.c\n", "PROXY TCP4 10.0.0.9 10.0.0.1 1 2\r\n"} {
		c := sf.f.dial(t, sf.f.c.PostgresBindings[0].Listen)
		io.WriteString(c, start)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply, _ := io.ReadAll(c)
		if bytes.Contains(reply, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
			t.Errorf("PostgreSQL stream opening %q got a password request", start)
		}
	}
	// Positive control: a valid startup does get the password request.
	c := sf.f.dial(t, sf.f.c.PostgresBindings[0].Listen)
	startup, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"user": "workload", "database": "appdb"}}).Encode(nil)
	c.Write(startup)
	reply := make([]byte, 9)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e := io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("positive control: %v %q", e, reply)
	}
	select {
	case got := <-sf.attested:
		t.Fatalf("a forged request reached the broker: %q", got)
	default:
	}
}

// Every Pod that is not exactly one admissible agent is refused.
func TestSharedLookupRefusals(t *testing.T) {
	ip := netip.MustParseAddr("10.8.0.4")
	cases := map[string]func(p map[string]any) []map[string]any{
		"owned by a ReplicaSet": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["kind"] = "ReplicaSet"
			return []map[string]any{p}
		},
		"owner from another API group": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["apiVersion"] = "example.com/v1"
			return []map[string]any{p}
		},
		"owner is not the controller": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["controller"] = false
			return []map[string]any{p}
		},
		"no blockOwnerDeletion": func(p map[string]any) []map[string]any {
			delete(p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any), "blockOwnerDeletion")
			return []map[string]any{p}
		},
		"unapproved image": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["containerStatuses"] = []any{map[string]any{"imageID": "r@" + sandboxDigest}, map[string]any{"imageID": "r@" + otherDigest}}
			return []map[string]any{p}
		},
		"ephemeral container added": func(p map[string]any) []map[string]any {
			p["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debug"}}
			return []map[string]any{p}
		},
		"host network": func(p map[string]any) []map[string]any {
			p["spec"].(map[string]any)["hostNetwork"] = true
			return []map[string]any{p}
		},
		"not running": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["phase"] = "Pending"
			return []map[string]any{p}
		},
		"past its deadline": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["startTime"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
			return []map[string]any{p}
		},
		"another namespace": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["namespace"] = "kube-system"
			return []map[string]any{p}
		},
		"two live Pods on one address": func(p map[string]any) []map[string]any {
			return []map[string]any{p, sandboxPod("sandbox-b", "pod-b", ip.String())}
		},
		"no Pod at the address": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["podIP"] = "10.8.0.5"
			return []map[string]any{p}
		},
	}
	for name, build := range cases {
		cache := &podCache{config: sharedConfig(), now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, inSync: map[string]bool{}, lostAt: map[string]time.Time{}}
		cache.replace("agent-sandboxes", decodePods(t, build(sandboxPod("sandbox-a", "pod-a", ip.String()))))
		if a, ok := cache.lookup(ip); ok {
			t.Errorf("%s: admitted %+v", name, a)
		}
	}
	// The positive control, and a stale watch.
	cache := &podCache{config: sharedConfig(), now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, inSync: map[string]bool{}, lostAt: map[string]time.Time{}}
	cache.replace("agent-sandboxes", decodePods(t, []map[string]any{sandboxPod("sandbox-a", "pod-a", ip.String())}))
	if _, ok := cache.lookup(ip); !ok {
		t.Fatal("admissible agent refused")
	}
	// The watch goes down: Pods stay admissible for outOfSync, then not.
	cache.lost("agent-sandboxes")
	if _, ok := cache.lookup(ip); !ok {
		t.Fatal("refused at once when the watch went down")
	}
	cache.now = func() time.Time { return time.Now().Add(outOfSync + time.Second) }
	if _, ok := cache.lookup(ip); ok {
		t.Fatal("admitted from a watch down for more than 10 seconds")
	}
	cache.heard("agent-sandboxes")
	if _, ok := cache.lookup(ip); !ok {
		t.Fatal("refused after the watch came back")
	}
}

func decodePods(t *testing.T, pods []map[string]any) []*agentPod {
	t.Helper()
	var out []*agentPod
	for _, p := range pods {
		b, _ := json.Marshal(p)
		var pod agentPod
		if e := json.Unmarshal(b, &pod); e != nil {
			t.Fatal(e)
		}
		out = append(out, &pod)
	}
	return out
}

func TestSharedConfigValidation(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:8443", Upstream: f.upstream(t, "broker.internal:443"), AllowedTargets: []string{"api.example.com:443"}}
		return c
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("valid shared config refused: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"also self": func(c *FixedConfig) { c.Self = true },
		"also paired": func(c *FixedConfig) {
			c.Sandbox = SandboxConfig{Namespace: "n", Name: "x", UID: "u", PodIP: "10.0.0.1", ContainerName: "c"}
		},
		"browser":              func(c *FixedConfig) { c.Browser = &BrowserConfig{Listen: "0.0.0.0:9443", Upstream: c.Connect.Upstream} },
		"session file":         func(c *FixedConfig) { c.Connect.Upstream.SessionFile = "/var/run/session" },
		"Cursor socket":        func(c *FixedConfig) { c.Connect.Upstream.SessionSocketDir = "/var/run/cursor-identity" },
		"no TLS":               func(c *FixedConfig) { c.TLSCertFile = "" },
		"no Kubernetes access": func(c *FixedConfig) { c.Kubernetes.ReviewerTokenFile = "" },
		"no profiles":          func(c *FixedConfig) { c.Shared.Profiles = nil },
		"bad namespace":        func(c *FixedConfig) { c.Shared.Profiles = map[string]string{"Agent_Sandboxes": "p"} },
		"empty profile":        func(c *FixedConfig) { c.Shared.Profiles = map[string]string{"agent-sandboxes": ""} },
		"no owner kind":        func(c *FixedConfig) { c.Shared.OwnerKind = "" },
		"bad API version":      func(c *FixedConfig) { c.Shared.OwnerAPIVersion = "agents" },
		"no image digests":     func(c *FixedConfig) { c.Shared.ImageDigests = nil },
		"image tag":            func(c *FixedConfig) { c.Shared.ImageDigests = []string{"agent:latest"} },
		"no Pod lifetime":      func(c *FixedConfig) { c.Shared.MaxPodSeconds = 0 },
		"too many connections": func(c *FixedConfig) { c.Shared.MaxConnections = 1 << 20 },
		"no listener":          func(c *FixedConfig) { c.Connect = nil },
	} {
		c := base()
		shared := *c.Shared
		c.Shared = &shared
		connect := *c.Connect
		c.Connect = &connect
		mutate(&c)
		if e := c.Validate(time.Now()); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A shared proxy may serve plaintext on the Pod network: CONNECT works, any
// other request is refused, a PostgreSQL client asking for TLS is told no and
// goes on, and admissions are audited with the agent Pod and its images.
func TestSharedProxyPlaintext(t *testing.T) {
	sf := startSharedWith(t, true, true)
	if _, _, status := sf.connect(t, ""); status != 200 {
		t.Fatalf("plaintext CONNECT: %d", status)
	}
	<-sf.attested
	for _, request := range []string{
		"GET http://approved.test/ HTTP/1.1\r\nHost: approved.test\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: approved.test\r\n\r\n",
		"POST http://approved.test:443/ HTTP/1.1\r\nHost: approved.test:443\r\nContent-Length: 0\r\n\r\n",
	} {
		c := sf.dial(t, sf.f.c.Connect.Listen)
		io.WriteString(c, request)
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err == nil {
			response.Body.Close()
		}
		if err == nil && response.StatusCode == 200 {
			t.Errorf("non-CONNECT request admitted: %q", request)
		}
	}
	// sslmode=prefer: SSLRequest, 'N', then the startup gets the password request.
	c := sf.dial(t, sf.f.c.PostgresBindings[0].Listen)
	c.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f})
	answer := make([]byte, 1)
	if _, err := io.ReadFull(c, answer); err != nil || answer[0] != 'N' {
		t.Fatalf("SSLRequest answer %q %v", answer, err)
	}
	startup, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"user": "workload", "database": "appdb"}}).Encode(nil)
	c.Write(startup)
	reply := make([]byte, 9)
	if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("startup after SSLRequest: %v %q", err, reply)
	}
	audit, _ := os.ReadFile(sf.f.c.AuditFile)
	if !bytes.Contains(audit, []byte(`"podUID":"pod-a"`)) || !bytes.Contains(audit, []byte(`"images":["registry.example/agent@`+sandboxDigest)) ||
		!bytes.Contains(audit, []byte(`"namespace":"agent-sandboxes"`)) {
		t.Fatalf("admission row lacks the agent: %s", audit)
	}
}

// Upstreams to the broker are TLS in every mode; a shared config cannot
// leave out the broker's name or CA, nor give a certificate without its key.
func TestSharedUpstreamsStayTLS(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.TLSCertFile, c.TLSKeyFile = "", ""
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:8443", Upstream: f.upstream(t, "broker.internal:16443"), AllowedTargets: []string{"api.example.com:443"}}
		return c
	}
	if err := base().Validate(time.Now()); err != nil {
		t.Fatalf("plaintext listeners refused: %v", err)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"no broker CA":        func(c *FixedConfig) { c.Connect.Upstream.CAFile = "" },
		"no broker name":      func(c *FixedConfig) { c.Connect.Upstream.ServerName = "" },
		"certificate, no key": func(c *FixedConfig) { c.TLSCertFile = "/tls/tls.crt" },
		"audit to stdout, paired": func(c *FixedConfig) {
			c.Shared, c.Sandbox = nil, SandboxConfig{ContainerName: "worker", Namespace: "sandboxes", Name: "agent", UID: "pod-uid", PodIP: "127.0.0.1"}
			c.TLSCertFile, c.TLSKeyFile, c.AuditFile = "/tls/tls.crt", "/tls/tls.key", StdoutAudit
		},
	} {
		c := base()
		connect := *c.Connect
		c.Connect = &connect
		mutate(&c)
		if name == "audit to stdout, paired" {
			// Paired relays keep a durable, synced audit file.
			if _, err := openAudit(c, func(string) error { return nil }); err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if err := c.Validate(time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	c.AuditFile = StdoutAudit
	if a, err := openAudit(c, func(string) error { return errDenied }); err != nil || !a.stdout {
		t.Fatalf("shared audit to stdout: %v", err)
	}
}

// Image prefixes: each namespace runs what its tenant path pulled; the proxy
// image in the same repository never counts; platform digests run anywhere.
func TestSharedImagePrefixes(t *testing.T) {
	const orion = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/"
	ip := netip.MustParseAddr("10.8.0.4")
	config := sharedConfig()
	config.ImagePrefixes = map[string]string{"agent-sandboxes": orion}
	for name, c := range map[string]struct {
		images []string
		ok     bool
	}{
		"tenant image":              {[]string{orion + "agent@" + otherDigest}, true},
		"tenant image and platform": {[]string{orion + "agent@" + otherDigest, "registry.example/gcsfuse@" + sandboxDigest}, true},
		"proxy image":               {[]string{"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/gatehouse/proxy@" + otherDigest}, false},
		"another tenant":            {[]string{"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/x@" + otherDigest}, false},
	} {
		pod := sandboxPod("sandbox-a", "pod-a", ip.String())
		var statuses []any
		for _, image := range c.images {
			statuses = append(statuses, map[string]any{"imageID": image})
		}
		pod["status"].(map[string]any)["containerStatuses"] = statuses[:1]
		pod["status"].(map[string]any)["initContainerStatuses"] = statuses[1:]
		cache := &podCache{config: config, now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, inSync: map[string]bool{}, lostAt: map[string]time.Time{}}
		cache.replace("agent-sandboxes", decodePods(t, []map[string]any{pod}))
		a, ok := cache.lookup(ip)
		if ok != c.ok || (ok && len(a.Images) != len(c.images)) {
			t.Errorf("%s: %v %+v", name, ok, a)
		}
	}
	f := newRelayFixture(t)
	for name, prefixes := range map[string]map[string]string{
		"another project":    {"agent-sandboxes": "us-central1-docker.pkg.dev/other/agent-sandbox-images-staging/orion/"},
		"no trailing slash":  {"agent-sandboxes": strings.TrimSuffix(orion, "/")},
		"unmapped namespace": {"other-sandboxes": orion},
		"overlap":            {"agent-sandboxes": orion, "orion-sandboxes": "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/"},
	} {
		c := f.c
		c.Sandbox = SandboxConfig{}
		s := *sharedConfig()
		s.Profiles = map[string]string{"agent-sandboxes": "a", "orion-sandboxes": "b"}
		s.ImagePrefixes = prefixes
		c.Shared = &s
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:8443", Upstream: f.upstream(t, "broker.internal:16443"), AllowedTargets: []string{"api.example.com:443"}}
		if err := c.Validate(time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The staging proxy's configuration (#2926), exactly: no deadline, no
// certificate, audit to stdout, image prefixes covering every namespace and
// no digests. With no listeners it is refused; with one it loads.
func TestStagingSharedConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(withListener bool) string {
		config := map[string]any{
			"taskID": "gatehouse-proxy-staging", "auditFile": "/dev/stdout",
			"kubernetes": map[string]any{"apiURL": "https://kubernetes.default.svc", "caFile": "/etc/task-relay/kube/ca.crt",
				"reviewerTokenFile": "/var/run/task-relay/proofs/api"},
			"shared": map[string]any{
				"profiles": map[string]any{"agent-sandboxes-staging": "agent-sandbox-orion-staging",
					"developers-sandboxes-staging": "agent-sandbox-developers-staging"},
				"imagePrefixes": map[string]any{
					"agent-sandboxes-staging":      "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/",
					"developers-sandboxes-staging": "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/"},
				"imageDigests": []any{}, "ownerKind": "Sandbox", "ownerAPIVersion": "agents.x-k8s.io/v1beta1", "maxPodSeconds": 28800},
		}
		if withListener {
			config["connect"] = map[string]any{"listen": "0.0.0.0:14443", "allowedTargets": []any{"api.example.com:443"},
				"upstream": map[string]any{"address": "10.65.1.2:16443", "serverName": "gatehouse-broker.staging.gatehouse.internal",
					"caFile": "/etc/task-relay/trust/ca.crt", "proofFile": "/var/run/task-relay/proofs/gatehouse", "audience": "gatehouse-broker-staging"}}
		}
		path := filepath.Join(dir, fmt.Sprintf("relay-%v.json", withListener))
		b, _ := json.Marshal(config)
		writeTestFile(t, path, b)
		return path
	}
	if _, err := LoadConfig(write(false)); err == nil {
		t.Error("a shared proxy with no listener loaded")
	}
	if _, err := LoadConfig(write(true)); err != nil {
		t.Errorf("the staging shared config with one listener refused: %v", err)
	}
}

func withRequester(pod map[string]any, requester string) map[string]any {
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{workloadidentity.RequesterAnnotation: requester, "other": "ignored"}
	return pod
}

// connectUntil retries a CONNECT until it gets want, for cache updates that
// land a moment after the watch event.
func (sf *sharedFixture) connectUntil(t *testing.T, want int) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); ; {
		c, b, status := sf.connect(t, "")
		if status == want || time.Now().After(end) {
			return c, b, status
		}
		c.Close()
		if status == 200 {
			<-sf.attested
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// In a namespace configured to carry it, the attestation and the admission
// row name the requester from the Pod's annotation. A Pod there without a
// valid one is not admitted, and an open connection ends if it changes.
func TestSharedProxyAttestsTheRequester(t *testing.T) {
	sf := startSharedWith(t, false, false, func(c *FixedConfig) { c.Shared.RequesterNamespaces = []string{"agent-sandboxes"} })
	if _, _, status := sf.connect(t, ""); status == 200 {
		t.Fatal("a Pod with no requester was admitted")
	}
	sf.api.send(t, "MODIFIED", withRequester(sandboxPod("sandbox-a", "pod-a", "127.0.0.1"), "alice.smith@trmlabs.com"))
	c, b, status := sf.connectUntil(t, 200)
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(<-sf.attested)
	var a workloadidentity.Attestation
	if json.Unmarshal(raw, &a) != nil || a.Requester != "alice.smith@trmlabs.com" || a.PodUID != "pod-a" {
		t.Fatalf("attestation %s", raw)
	}
	audit, _ := os.ReadFile(sf.f.c.AuditFile)
	if !bytes.Contains(audit, []byte(`"requester":"alice.smith@trmlabs.com"`)) {
		t.Fatalf("admission row lacks the requester: %s", audit)
	}
	sf.api.send(t, "MODIFIED", withRequester(sandboxPod("sandbox-a", "pod-a", "127.0.0.1"), "bob.jones@trmlabs.com"))
	if !tunnelCloses(t, c, b) {
		t.Fatal("a connection stayed open after its requester changed")
	}
	for _, bad := range []string{"", "Alice.Smith@trmlabs.com", "alice", "alice@", "alice@trmlabs", "alice smith@trmlabs.com", "alice@trmlabs.com\n", strings.Repeat("a", 65) + "@trmlabs.com"} {
		sf.api.send(t, "MODIFIED", withRequester(sandboxPod("sandbox-a", "pod-a", "127.0.0.1"), "carol@trmlabs.com"))
		if _, _, status := sf.connectUntil(t, 200); status != 200 {
			t.Fatalf("valid requester refused: %d", status)
		}
		<-sf.attested
		sf.api.send(t, "MODIFIED", withRequester(sandboxPod("sandbox-a", "pod-a", "127.0.0.1"), bad))
		if _, _, status := sf.connectUntil(t, 403); status == 200 {
			t.Fatalf("requester %q admitted", bad)
		}
	}
}

// Elsewhere the attestation never carries a requester, even when the Pod has
// the annotation, and the namespace list must name configured namespaces.
func TestSharedProxyRequesterIsOptIn(t *testing.T) {
	s := sharedConfig()
	pod := decodePods(t, []map[string]any{withRequester(sandboxPod("sandbox-a", "pod-a", "127.0.0.1"), "alice.smith@trmlabs.com")})[0]
	if a, ok := pod.attest(s, time.Now()); !ok || a.Requester != "" {
		t.Fatalf("requester attested without opt-in: %+v %v", a, ok)
	}
	s.RequesterNamespaces = []string{"agent-sandboxes"}
	if a, ok := pod.attest(s, time.Now()); !ok || a.Requester != "alice.smith@trmlabs.com" {
		t.Fatalf("opted-in requester: %+v %v", a, ok)
	}
	for name, namespaces := range map[string][]string{
		"unknown namespace": {"other-sandboxes"},
		"repeated":          {"agent-sandboxes", "agent-sandboxes"},
	} {
		s := sharedConfig()
		s.RequesterNamespaces = namespaces
		if s.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

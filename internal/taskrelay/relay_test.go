package taskrelay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type relayFixture struct {
	c        FixedConfig
	cert     tls.Certificate
	state    atomic.Int32
	kube     *httptest.Server
	done     chan struct{}
	runError error
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	f := &relayFixture{}
	dir := t.TempDir()
	f.kube = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/sandboxes/pods/agent" || r.Header.Get("Authorization") != "Bearer synthetic-reviewer" {
			w.WriteHeader(403)
			return
		}
		uid, phase, ip := "pod-uid", "Running", "127.0.0.1"
		var deletion any
		switch f.state.Load() {
		case 1:
			uid = "replacement"
		case 2:
			phase = "Pending"
		case 3:
			deletion = "now"
		case 4:
			ip = "127.0.0.2"
		case 5:
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": "agent", "namespace": "sandboxes", "uid": uid, "deletionTimestamp": deletion}, "status": map[string]any{"phase": phase, "podIP": ip}})
	}))
	t.Cleanup(f.kube.Close)
	f.cert = f.kube.TLS.Certificates[0]
	ca := filepath.Join(dir, "ca.pem")
	writeTestFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Certificate[0]}))
	key, _ := x509.MarshalPKCS8PrivateKey(f.cert.PrivateKey)
	keyFile := filepath.Join(dir, "key.pem")
	writeTestFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	reviewer := filepath.Join(dir, "reviewer")
	writeTestFile(t, reviewer, []byte("synthetic-reviewer"))
	f.c = FixedConfig{TaskID: "task-one", Deadline: time.Now().Add(time.Hour), Sandbox: SandboxConfig{Namespace: "sandboxes", Name: "agent", UID: "pod-uid", PodIP: "127.0.0.1"}, Kubernetes: KubernetesConfig{APIURL: f.kube.URL, CAFile: ca, ReviewerTokenFile: reviewer}, TLSCertFile: ca, TLSKeyFile: keyFile, AuditFile: filepath.Join(dir, "audit.jsonl")}
	return f
}
func writeTestFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func testProof(exp time.Time, aud string) string {
	b, _ := json.Marshal(map[string]any{"exp": exp.Unix(), "aud": []string{aud}})
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".synthetic"
}
func (f *relayFixture) upstream(t *testing.T, address string) UpstreamConfig {
	p := filepath.Join(t.TempDir(), "proof")
	writeTestFile(t, p, []byte(testProof(time.Now().Add(time.Hour), "gatehouse")))
	return UpstreamConfig{Address: address, ServerName: "127.0.0.1", CAFile: f.c.TLSCertFile, ProofFile: p, Audience: "gatehouse"}
}
func freeAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func (f *relayFixture) start(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	done := make(chan struct{})
	f.done = done
	go func() { f.runError = Run(ctx, f.c); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	address := ""
	switch {
	case f.c.Connect != nil:
		address = f.c.Connect.Listen
	case f.c.Postgres != nil:
		address = f.c.Postgres.Listen
	default:
		address = f.c.Browser.Listen
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		conn, e := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if e == nil {
			conn.Close()
			return
		}
		select {
		case <-done:
			t.Fatalf("relay failed: %v", f.runError)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay did not listen")
}
func (f *relayFixture) dial(t *testing.T, address string) net.Conn {
	t.Helper()
	tc, e := clientTLS(f.c.TLSCertFile, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, tc)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(4 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func TestPairVerifierRejectsChangedIdentityAndSpoofedPeer(t *testing.T) {
	f := newRelayFixture(t)
	v, e := newPairVerifier(f.c)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.check(context.Background(), "127.0.0.1:1234"); e != nil {
		t.Fatal(e)
	}
	for _, peer := range []string{"127.0.0.2:1234", "spoofed", ""} {
		if peer == "" {
			continue
		}
		if v.check(context.Background(), peer) == nil {
			t.Fatal("accepted wrong peer")
		}
	}
	for state := int32(1); state <= 5; state++ {
		f.state.Store(state)
		if v.check(context.Background(), "127.0.0.1:1234") == nil {
			t.Fatalf("accepted state %d", state)
		}
	}
}

func TestConnectCustodyRotationAndPairRevocation(t *testing.T) {
	f := newRelayFixture(t)
	proofs := make(chan string, 10)
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proofs <- r.Header.Get("Proxy-Authorization")
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 200 OK\r\nX-Reflected-Proof: " + r.Header.Get("Proxy-Authorization") + "\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	}))
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	broker.StartTLS()
	defer broker.Close()
	f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
	f.start(t)
	connect := func(extra string) (net.Conn, *bufio.Reader, *http.Response) {
		c := f.dial(t, f.c.Connect.Listen)
		io.WriteString(c, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n"+extra+"\r\n")
		b := bufio.NewReader(c)
		response, e := http.ReadResponse(b, &http.Request{Method: "CONNECT"})
		if e != nil {
			t.Fatal(e)
		}
		return c, b, response
	}
	c, b, firstResponse := connect("")
	defer func() { c.Close(); firstResponse.Body.Close() }()
	if firstResponse.StatusCode != 200 || len(firstResponse.Header) != 0 {
		t.Fatalf("unsafe response: %v", firstResponse.StatusCode)
	}
	old := <-proofs
	io.WriteString(c, "hello")
	echo := make([]byte, 5)
	if _, e := io.ReadFull(b, echo); e != nil || string(echo) != "hello" {
		t.Fatal("tunnel did not relay")
	}
	_, _, denied := connect("Proxy-Authorization: Bearer attacker\r\n")
	if denied.StatusCode != 403 {
		t.Fatal("accepted caller identity")
	}
	denied.Body.Close()
	_, _, denied = connect("X-Forwarded-For: 127.0.0.1\r\n")
	if denied.StatusCode != 403 {
		t.Fatal("accepted forwarded identity")
	}
	denied.Body.Close()
	fresh := testProof(time.Now().Add(2*time.Hour), "gatehouse")
	writeTestFile(t, f.c.Connect.Upstream.ProofFile, []byte(fresh))
	second, _, response := connect("")
	defer func() { second.Close(); response.Body.Close() }()
	if response.StatusCode != 200 {
		t.Fatal("rotation failed")
	}
	second.Close()
	if got := <-proofs; got == old || got != "Bearer "+fresh {
		t.Fatal("proof not freshly read")
	}
	f.state.Store(1)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, e := b.ReadByte(); e == nil {
		t.Fatal("pair loss left tunnel alive")
	}
	audit, _ := os.ReadFile(f.c.AuditFile)
	if strings.Contains(string(audit), fresh) || !strings.Contains(string(audit), "pod-uid") {
		t.Fatal("unsafe audit")
	}
}

func TestConfigAndProofFailClosed(t *testing.T) {
	f := newRelayFixture(t)
	up := f.upstream(t, "127.0.0.1:443")
	f.c.Connect = &ConnectConfig{Listen: "127.0.0.1:14443", Upstream: up, AllowedTargets: []string{"approved.test:443"}}
	if e := f.c.Validate(time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{testProof(time.Now().Add(-time.Minute), "gatehouse"), testProof(time.Now().Add(time.Hour), "wrong"), "not-a-proof"} {
		writeTestFile(t, up.ProofFile, []byte(value))
		if _, _, e := readProof(up, f.c.Deadline); e == nil {
			t.Fatal("accepted invalid proof")
		}
	}
	f.c.Deadline = time.Now().Add(9 * time.Hour)
	if f.c.Validate(time.Now()) == nil {
		t.Fatal("accepted excessive deadline")
	}
	f.c.Deadline = time.Now().Add(time.Hour)
	f.c.AuditFile = ""
	if f.c.Validate(time.Now()) == nil {
		t.Fatal("accepted missing durable audit")
	}
}

func TestPostgresCustodyAndCancellation(t *testing.T) {
	f := newRelayFixture(t)
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	proofs := make(chan string, 4)
	cancels := make(chan []byte, 4)
	coreKey := []byte{0, 0, 0, 7, 0, 0, 0, 9}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				packet, e := readStartupPacket(c)
				if e != nil {
					return
				}
				if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
					cancels <- packet
					return
				}
				c.Write(encodePGFrame('R', []byte{0, 0, 0, 3}))
				typ, p, e := readPGFrame(c, 32768)
				if e != nil || typ != 'p' {
					return
				}
				proofs <- strings.TrimSuffix(string(p), "\x00")
				c.Write(encodePGFrame('R', []byte{0, 0, 0, 0}))
				c.Write(encodePGFrame('K', coreKey))
				c.Write(encodePGFrame('Z', []byte{'I'}))
				io.Copy(c, c)
			}()
		}
	}()
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, l.Addr().String()), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	c := f.dial(t, f.c.Postgres.Listen)
	startup, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "canary"}}).Encode(nil)
	c.Write(startup)
	typ, b, e := readPGFrame(c, 1024)
	if e != nil || typ != 'R' || binary.BigEndian.Uint32(b) != 3 {
		t.Fatal("missing placeholder prompt")
	}
	c.Write(encodePGFrame('p', []byte("public-placeholder\x00")))
	var localKey []byte
	for {
		typ, b, e = readPGFrame(c, 8192)
		if e != nil {
			t.Fatal(e)
		}
		if typ == 'K' {
			localKey = b
		}
		if typ == 'Z' {
			break
		}
	}
	if string(localKey) == string(coreKey) || len(localKey) != 8 {
		t.Fatal("broker cancel key disclosed")
	}
	expected, _ := os.ReadFile(f.c.Postgres.Upstream.ProofFile)
	if got := <-proofs; got != string(expected) {
		t.Fatal("proof not substituted")
	}
	sendCancel := func(key []byte) {
		cc := f.dial(t, f.c.Postgres.Listen)
		packet := binary.BigEndian.AppendUint32(nil, 16)
		packet = binary.BigEndian.AppendUint32(packet, cancelCode)
		packet = append(packet, key...)
		cc.Write(packet)
		io.Copy(io.Discard, cc)
		cc.Close()
	}
	sendCancel(coreKey)
	select {
	case <-cancels:
		t.Fatal("accepted broker key directly")
	default:
	}
	sendCancel(localKey)
	select {
	case got := <-cancels:
		if string(got[8:]) != string(coreKey) {
			t.Fatal("wrong cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach broker")
	}
	c.Close()
	time.Sleep(30 * time.Millisecond)
	sendCancel(localKey)
	select {
	case <-cancels:
		t.Fatal("accepted stale cancellation key")
	default:
	}
}

func TestConnectProofExpiryClosesExistingTunnel(t *testing.T) {
	f := newRelayFixture(t)
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer broker.Close()
	f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
	expiry := time.Now().Add(2 * time.Second)
	writeTestFile(t, f.c.Connect.Upstream.ProofFile, []byte(testProof(expiry, "gatehouse")))
	f.start(t)
	c := f.dial(t, f.c.Connect.Listen)
	io.WriteString(c, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n\r\n")
	reader := bufio.NewReader(c)
	response, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("not established: %v", e)
	}
	defer func() { c.Close(); response.Body.Close() }()
	c.SetReadDeadline(expiry.Add(time.Second))
	if _, e = reader.ReadByte(); e == nil {
		t.Fatal("proof expiry did not close tunnel")
	} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("relay did not enforce proof expiry")
	}
}

func TestPostgresDeniesAuthorityAndMalformedFramesBeforeUpstream(t *testing.T) {
	f := newRelayFixture(t)
	var calls atomic.Int32
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
			calls.Add(1)
			c.Close()
		}
	}()
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, l.Addr().String()), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	for _, parameters := range []map[string]string{{"user": "workload", "database": "other"}, {"user": "workload", "database": "canary", "replication": "true"}, {"user": "workload", "database": "canary", "agent_vault_vault": "other"}, {"user": "workload", "database": "canary", "options": "-c role=admin"}} {
		c := f.dial(t, f.c.Postgres.Listen)
		b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
		c.Write(b)
		if _, e := c.Read(make([]byte, 1)); e == nil {
			t.Fatal("accepted invalid startup")
		}
		c.Close()
	}
	c := f.dial(t, f.c.Postgres.Listen)
	c.Write([]byte{255, 255, 255, 255})
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("accepted oversized startup")
	}
	c.Close()
	c = f.dial(t, f.c.Postgres.Listen)
	b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": "canary", "client_encoding": "UTF8"}}).Encode(nil)
	c.Write(b)
	if typ, _, e := readPGFrame(c, 1024); e != nil || typ != 'R' {
		t.Fatal("compatible startup not accepted")
	}
	c.Write(encodePGFrame('p', []byte("attacker-proof\x00")))
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("accepted nonplaceholder")
	}
	c.Close()
	if calls.Load() != 0 {
		t.Fatal("denied request reached upstream")
	}
}

func TestAuditFailureCancelsTaskBeforeAdmission(t *testing.T) {
	f := newRelayFixture(t)
	a, e := newAudit(f.c)
	if e != nil {
		t.Fatal(e)
	}
	a.file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, e := newPairVerifier(f.c)
	if e != nil {
		t.Fatal(e)
	}
	r := &relay{config: f.c, pair: p, audit: a, ctx: ctx, cancel: cancel}
	if r.admit(ctx, "127.0.0.1:1234", "connect") == nil || ctx.Err() == nil {
		t.Fatal("audit failure did not revoke admission")
	}
}

func TestLoadConfigRejectsAmbiguousAndOversizedInput(t *testing.T) {
	f := newRelayFixture(t)
	f.c.Connect = &ConnectConfig{Listen: "127.0.0.1:14443", Upstream: f.upstream(t, "127.0.0.1:443"), AllowedTargets: []string{"approved.test:443"}}
	valid, _ := json.Marshal(f.c)
	path := filepath.Join(t.TempDir(), "config.json")
	writeTestFile(t, path, valid)
	if _, e := LoadConfig(path); e != nil {
		t.Fatal(e)
	}
	for _, input := range []string{string(valid) + " {}", strings.TrimSuffix(string(valid), "}") + `,"agentIdentityHeader":"attacker"}`, strings.Repeat(" ", 65537)} {
		writeTestFile(t, path, []byte(input))
		if _, e := LoadConfig(path); e != errConfig {
			t.Fatalf("want sanitized config refusal, got %v", e)
		}
	}
}

func TestConnectDeniesUnapprovedDestinationBeforeUpstream(t *testing.T) {
	f := newRelayFixture(t)
	var calls atomic.Int32
	broker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer broker.Close()
	f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
	f.start(t)
	for _, raw := range []string{"CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n", "GET https://approved.test/ HTTP/1.1\r\nHost: approved.test\r\n\r\n", "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\nAuthorization: Bearer attacker\r\n\r\n", "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\nContent-Length: 1\r\n\r\nx"} {
		c := f.dial(t, f.c.Connect.Listen)
		io.WriteString(c, raw)
		resp, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil || resp.StatusCode != 403 {
			t.Fatalf("request not denied: %v", e)
		}
		c.Close()
		resp.Body.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("denied destination reached broker")
	}
}

func TestSupervisorCanCloseBrowserAfterTaskDeadline(t *testing.T) {
	for _, refuseClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "refused"}[refuseClose], func(t *testing.T) {
			f := newRelayFixture(t)
			closed := make(chan struct{}, 1)
			broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/browser/tasks":
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(map[string]any{"handle": strings.Repeat("A", 43), "expiresAt": time.Now().Add(time.Minute).UnixMilli()})
				case "/v1/browser/close":
					closed <- struct{}{}
					if refuseClose {
						w.WriteHeader(503)
						return
					}
					io.WriteString(w, `{"closed":true}`)
				default:
					w.WriteHeader(404)
				}
			}))
			broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
			broker.StartTLS()
			defer broker.Close()
			f.c.Deadline = time.Now().Add(time.Second)
			f.c.Browser = &BrowserConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String())}
			f.start(t)
			tc, e := clientTLS(f.c.TLSCertFile, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: time.Second}
			defer client.CloseIdleConnections()
			response, e := client.Post("https://"+f.c.Browser.Listen+"/v1/browser/tasks", "application/json", strings.NewReader("{}"))
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			if response.StatusCode != 201 {
				t.Fatalf("create status %d", response.StatusCode)
			}
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("supervisor could not close browser after task deadline")
			}
			select {
			case <-f.done:
			case <-time.After(time.Second):
				t.Fatal("relay shutdown did not finish")
			}
			if refuseClose && f.runError != errDenied {
				t.Fatalf("want cleanup failure, got %v", f.runError)
			}
			if !refuseClose && f.runError != nil {
				t.Fatalf("clean shutdown failed: %v", f.runError)
			}
		})
	}
}

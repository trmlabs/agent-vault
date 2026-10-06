package taskrelay

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

var proxyNames = []string{"gatehouse-proxy.agent-sandbox.svc", "gatehouse-proxy.agent-sandbox.svc.cluster.local"}

// testIssuer stands in for the broker's cross-cluster listener: it answers
// CONNECT like the HTTP proxy and signs certificate requests like the
// proxy-certificate route, with its own CA.
type testIssuer struct {
	srv     *httptest.Server
	caFile  string
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte
	roots   *x509.CertPool
	ttl     atomic.Int64
	fail    atomic.Bool
	issued  atomic.Int32
	bearers chan string
}

func newTestIssuer(t *testing.T, ttl time.Duration) *testIssuer {
	t.Helper()
	ti := &testIssuer{bearers: make(chan string, 64)}
	ti.ttl.Store(int64(ttl))
	ti.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test proxy CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, ti.caKey.Public(), ti.caKey)
	if e != nil {
		t.Fatal(e)
	}
	ti.ca, _ = x509.ParseCertificate(der)
	ti.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ti.roots = x509.NewCertPool()
	ti.roots.AddCert(ti.ca)
	ti.srv = httptest.NewTLSServer(http.HandlerFunc(ti.serve))
	t.Cleanup(ti.srv.Close)
	ti.caFile = filepath.Join(t.TempDir(), "broker-ca.pem")
	writeTestFile(t, ti.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ti.srv.Certificate().Raw}))
	return ti
}

func (ti *testIssuer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != ProxyCertificatePath || ti.fail.Load() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case ti.bearers <- r.Header.Get("Authorization"):
	default:
	}
	var body struct{ CSR string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	// The broker's rule: a P-256 key, a valid signature, only the proxy's names.
	if e != nil || csr.CheckSignature() != nil || !ok || key.Curve != elliptic.P256() || !slices.Equal(csr.DNSNames, proxyNames) ||
		len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) != 0 {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	n := ti.issued.Add(1)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + n)), Subject: pkix.Name{CommonName: csr.Subject.CommonName}, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(time.Duration(ti.ttl.Load())),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ti.ca, key, ti.caKey)
	if e != nil {
		http.Error(w, "bad", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "chain": string(ti.caPEM)})
}

// startIssued runs a shared proxy with a broker-issued certificate on its
// CONNECT listener, one PostgreSQL binding and the single PostgreSQL port.
func startIssued(t *testing.T, ttl time.Duration) (*sharedFixture, *testIssuer) {
	t.Helper()
	ti := newTestIssuer(t, ttl)
	sf := startSharedWith(t, true, true, func(c *FixedConfig) {
		u, _ := url.Parse(ti.srv.URL)
		c.Connect.Upstream.Address, c.Connect.Upstream.CAFile = u.Host, ti.caFile
		c.TLS = &ServingTLSConfig{Mode: brokerIssued, Names: proxyNames}
		c.PostgresListener = &PostgresListenerConfig{Listen: freeAddress(t), Upstream: c.PostgresBindings[0].Upstream, Databases: []string{"appdb", "reporting"},
			User: "workload", Placeholder: "placeholder"}
	})
	return sf, ti
}

// dialProxy opens TLS to a proxy listener the way an agent would: verifying
// the broker CA and the proxy's Service name.
func (ti *testIssuer) dialProxy(address string) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: ti.roots, ServerName: proxyNames[0]})
}

// pgUpgrade sends optional GSSENCRequest, then SSLRequest, expects 'S' and
// returns the TLS session.
func (ti *testIssuer) pgUpgrade(t *testing.T, address string, gssFirst bool) *tls.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(4 * time.Second))
	answer := make([]byte, 1)
	if gssFirst {
		c.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, gssRequestCode))
		if _, e := io.ReadFull(c, answer); e != nil || answer[0] != 'N' {
			t.Fatalf("GSSENCRequest answered %q %v", answer, e)
		}
	}
	c.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, sslRequestCode))
	if _, e := io.ReadFull(c, answer); e != nil || answer[0] != 'S' {
		t.Fatalf("SSLRequest answered %q %v", answer, e)
	}
	secure := tls.Client(c, &tls.Config{RootCAs: ti.roots, ServerName: proxyNames[0], NextProtos: []string{"postgresql"}})
	if e := secure.Handshake(); e != nil {
		t.Fatalf("PostgreSQL TLS handshake: %v", e)
	}
	return secure
}

func startupFor(database string) []byte {
	b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"user": "workload", "database": database}}).Encode(nil)
	return b
}

// With a broker-issued certificate every agent-facing listener is TLS under
// the broker CA: CONNECT, each PostgreSQL binding and the single port. A
// PostgreSQL client gets 'S' for its SSLRequest (after 'N' for GSS
// encryption); a plaintext startup or cancellation is refused in fixed words.
// The request carried the proxy's own token and only its names.
func TestBrokerIssuedTLSOnEveryListener(t *testing.T) {
	sf, ti := startIssued(t, time.Hour)
	token, _ := os.ReadFile(sf.f.c.Connect.Upstream.ProofFile)
	if bearer := <-ti.bearers; bearer != "Bearer "+strings.TrimSpace(string(token)) {
		t.Fatal("certificate request did not carry the proxy's token")
	}
	c, e := ti.dialProxy(sf.f.c.Connect.Listen)
	if e != nil {
		t.Fatalf("CONNECT listener TLS: %v", e)
	}
	if status := connectStatus(c); status != 200 {
		t.Fatalf("CONNECT over TLS: %d", status)
	}
	plain, _ := net.DialTimeout("tcp", sf.f.c.Connect.Listen, time.Second)
	plain.SetDeadline(time.Now().Add(4 * time.Second))
	if connectStatus(plain) == 200 {
		t.Fatal("plaintext CONNECT admitted")
	}
	plain.Close()
	for _, address := range []string{sf.f.c.PostgresBindings[0].Listen, sf.f.c.PostgresListener.Listen} {
		for _, gss := range []bool{false, true} {
			secure := ti.pgUpgrade(t, address, gss)
			secure.Write(startupFor("appdb"))
			if typ, body, e := readPGFrame(secure, 1024); e != nil || typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
				t.Fatalf("%s: startup inside TLS: %c %v", address, typ, e)
			}
		}
		cancel := append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 16), cancelCode), 1, 2, 3, 4, 5, 6, 7, 8)
		for _, first := range [][]byte{startupFor("appdb"), cancel} {
			plain, _ := net.DialTimeout("tcp", address, time.Second)
			plain.SetDeadline(time.Now().Add(4 * time.Second))
			plain.Write(first)
			typ, body, e := readPGFrame(plain, 8192)
			if e != nil || typ != 'E' || sqlState(body) != "28000" || errorField(body, 'M') != plaintextRefusedMessage {
				t.Fatalf("%s: plaintext not refused: %c %q %v", address, typ, body, e)
			}
			plain.Close()
		}
	}
	// The single port still routes by catalog inside TLS.
	secure := ti.pgUpgrade(t, sf.f.c.PostgresListener.Listen, false)
	secure.Write(startupFor("not-in-catalog"))
	if typ, body, e := readPGFrame(secure, 8192); e != nil || typ != 'E' || sqlState(body) != "3D000" {
		t.Fatalf("unknown database inside TLS: %c %v", typ, e)
	}
	audit, _ := os.ReadFile(sf.f.c.AuditFile)
	if bytes.Count(audit, []byte(`"certificate-issued"`)) != 1 || bytes.Count(audit, []byte(`denied:plaintext`)) != 4 {
		t.Fatalf("audit lacks issuance or plaintext refusals: %s", audit)
	}
}

// connectStatus sends a CONNECT and returns the response status, 0 if none.
func connectStatus(c net.Conn) int {
	io.WriteString(c, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n\r\n")
	response, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if e != nil {
		return 0
	}
	response.Body.Close()
	return response.StatusCode
}

func servedSerial(t *testing.T, ti *testIssuer, address string) (*big.Int, error) {
	t.Helper()
	c, e := ti.dialProxy(address)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber, nil
}

// The proxy renews at two thirds of the certificate's life on a new key,
// keeps serving the old one while the broker refuses, and refuses every
// handshake once it has expired with no replacement.
func TestBrokerIssuedCertificateRenewsAndExpires(t *testing.T) {
	sf, ti := startIssued(t, 3*time.Second)
	address := sf.f.c.Connect.Listen
	c, e := ti.dialProxy(address)
	if e != nil {
		t.Fatal(e)
	}
	leaf := c.ConnectionState().PeerCertificates[0]
	c.Close()
	first, life := leaf.SerialNumber, leaf.NotAfter.Sub(leaf.NotBefore)
	time.Sleep(time.Until(leaf.NotBefore.Add(life / 2)))
	if n := ti.issued.Load(); n != 1 {
		t.Fatalf("%d issuances by half the lifetime, want 1", n)
	}
	for deadline := leaf.NotBefore.Add(life * 4 / 5); ti.issued.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	ti.fail.Store(true)
	if n := ti.issued.Load(); n != 2 {
		t.Fatalf("%d issuances by four fifths of the lifetime, want 2", n)
	}
	second, e := servedSerial(t, ti, address)
	if e != nil || second.Cmp(first) == 0 {
		t.Fatalf("renewed certificate not served: %v", e)
	}
	c, e = ti.dialProxy(address)
	if e != nil {
		t.Fatal(e)
	}
	renewed := c.ConnectionState().PeerCertificates[0]
	c.Close()
	// Broker down: the current certificate serves until it expires.
	if _, e := servedSerial(t, ti, address); e != nil {
		t.Fatalf("current certificate withdrawn before expiry: %v", e)
	}
	time.Sleep(time.Until(renewed.NotAfter) + 300*time.Millisecond)
	// The proxy offers no certificate at all: even a client whose clock says
	// the expired one is still current gets none.
	earlier := &tls.Config{RootCAs: ti.roots, ServerName: proxyNames[0], Time: func() time.Time { return renewed.NotBefore.Add(time.Second) }}
	if c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, earlier); e == nil {
		c.Close()
		t.Fatal("handshake succeeded after expiry with no replacement")
	}
	secure, e := net.DialTimeout("tcp", sf.f.c.PostgresListener.Listen, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer secure.Close()
	secure.SetDeadline(time.Now().Add(4 * time.Second))
	secure.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, sslRequestCode))
	answer := make([]byte, 1)
	io.ReadFull(secure, answer)
	if tls.Client(secure, earlier).Handshake() == nil {
		t.Fatal("PostgreSQL handshake succeeded after expiry")
	}
	ti.fail.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := servedSerial(t, ti, address); e == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("serving did not resume once the broker issued again")
}

// The issued certificate must be for the proxy's own key, current, for
// server authentication, and name nothing beyond the configured names.
func TestBrokerIssuedCertificateChecks(t *testing.T) {
	ti := newTestIssuer(t, time.Hour)
	s := newServingCert(&ServingTLSConfig{Mode: brokerIssued, Names: proxyNames}, UpstreamConfig{})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issue := func(mutate func(*x509.Certificate), public any) string {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: proxyNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if mutate != nil {
			mutate(leaf)
		}
		der, _ := x509.CreateCertificate(rand.Reader, leaf, ti.ca, public, ti.caKey)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	good := issue(nil, key.Public())
	if cert, _, e := s.check(key, good, string(ti.caPEM), time.Now()); e != nil || len(cert.Certificate) != 2 {
		t.Fatalf("good certificate refused: %v", e)
	}
	if cert, _, e := s.check(key, good, good+string(ti.caPEM), time.Now()); e != nil || len(cert.Certificate) != 2 {
		t.Fatalf("leaf repeated in the chain: %v", e)
	}
	for name, certificate := range map[string]string{
		"other key":   issue(nil, other.Public()),
		"extra name":  issue(func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "elsewhere.example") }, key.Public()),
		"IP name":     issue(func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.IPv4(10, 0, 0, 1)} }, key.Public()),
		"no names":    issue(func(c *x509.Certificate) { c.DNSNames = nil }, key.Public()),
		"expired":     issue(func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }, key.Public()),
		"not yet":     issue(func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, key.Public()),
		"client auth": issue(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, key.Public()),
		"empty":       "",
		"not a cert":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"trailing":    good + "junk",
	} {
		if _, _, e := s.check(key, certificate, string(ti.caPEM), time.Now()); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Broker-issued TLS is shared mode only, takes the place of certificate
// files, needs the CONNECT upstream to ask over, and only lower-case DNS
// names, each once.
func TestServingTLSValidation(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.TLSCertFile, c.TLSKeyFile = "", ""
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:3128", Upstream: f.upstream(t, "broker.internal:443"), AllowedTargets: []string{"api.example.com:443"}}
		c.TLS = &ServingTLSConfig{Mode: brokerIssued, Names: proxyNames}
		return c
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("valid config refused: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"not shared":      func(c *FixedConfig) { c.Shared = nil },
		"other mode":      func(c *FixedConfig) { c.TLS.Mode = "files" },
		"no names":        func(c *FixedConfig) { c.TLS.Names = nil },
		"upper case name": func(c *FixedConfig) { c.TLS.Names = []string{"Gatehouse-Proxy"} },
		"IP name":         func(c *FixedConfig) { c.TLS.Names = []string{"10.0.0.1:443"} },
		"wildcard":        func(c *FixedConfig) { c.TLS.Names = []string{"*.agent-sandbox.svc"} },
		"repeated name":   func(c *FixedConfig) { c.TLS.Names = []string{proxyNames[0], proxyNames[0]} },
		"also files":      func(c *FixedConfig) { c.TLSCertFile, c.TLSKeyFile = f.c.TLSCertFile, f.c.TLSKeyFile },
		"no CONNECT": func(c *FixedConfig) {
			c.Connect = nil
			c.PostgresBindings = []PostgresConfig{{Listen: "0.0.0.0:5432", Upstream: f.upstream(t, "broker.internal:443"), Database: "a", User: "u", Placeholder: "p"}}
		},
	} {
		c := base()
		tlsConfig := *c.TLS
		c.TLS = &tlsConfig
		mutate(&c)
		if e := c.Validate(time.Now()); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

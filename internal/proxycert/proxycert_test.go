package proxycert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

var proxyNames = []string{"gatehouse-proxy.gatehouse-proxy.svc.cluster.local", "gatehouse-proxy.gatehouse-proxy.svc"}

func csrPEM(t *testing.T, key any, tmpl x509.CertificateRequest) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

type basicConstraints struct {
	IsCA bool `asn1:"optional"`
}

func ext(t *testing.T, id asn1.ObjectIdentifier, value any) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: id, Value: der}
}

func keyUsage(bits ...int) asn1.BitString {
	b := asn1.BitString{Bytes: []byte{0}, BitLength: 8}
	for _, bit := range bits {
		b.Bytes[0] |= 0x80 >> bit
	}
	return b
}

// A request may carry the extensions a serving certificate needs and nothing
// else: server authentication alone, and digital signature or key agreement.
func TestCheckRequestAllowsServingExtensions(t *testing.T) {
	key := p256(t)
	csr := csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{
		ext(t, oidExtKeyUsage, []asn1.ObjectIdentifier{oidServerAuth}), ext(t, oidKeyUsage, keyUsage(0, 4))}})
	if _, err := CheckRequest(csr, proxyNames); err != nil {
		t.Fatalf("serving extensions refused: %v", err)
	}
}

// The broker may list any number of proxy service names.
func TestIssuerTakesManyNames(t *testing.T) {
	var names []string
	for i := range 2000 {
		names = append(names, fmt.Sprintf("proxy-%d.tenant-%d.svc", i, i))
	}
	i := Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: names, TTL: 24 * time.Hour, Signer: &fakeSigner{}, Verifier: &fakeVerifier{}, Audit: &fakeAudit{}}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckRequest(csrPEM(t, p256(t), x509.CertificateRequest{DNSNames: names}), names); err != nil || len(got) != 2000 {
		t.Fatalf("2,000 names: %d, %v", len(got), err)
	}
}

func TestCheckRequestSignsOnlyTheProxysNames(t *testing.T) {
	key := p256(t)
	good := csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames})
	if names, err := CheckRequest(good, proxyNames); err != nil || len(names) != 2 {
		t.Fatalf("a request for the proxy's names was refused: %v %v", names, err)
	}
	if _, err := CheckRequest(csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames[:1], Subject: pkix.Name{CommonName: proxyNames[0]}}), proxyNames); err != nil {
		t.Fatalf("a subset with a matching common name was refused: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tampered := []byte(good)
	tampered[len(tampered)/2] ^= 1
	for name, csr := range map[string]string{
		"another name":        csrPEM(t, key, x509.CertificateRequest{DNSNames: []string{"vault.example.com"}}),
		"one extra name":      csrPEM(t, key, x509.CertificateRequest{DNSNames: append([]string{"evil.example.com"}, proxyNames...)}),
		"wildcard":            csrPEM(t, key, x509.CertificateRequest{DNSNames: []string{"*.svc.cluster.local"}}),
		"no names":            csrPEM(t, key, x509.CertificateRequest{Subject: pkix.Name{CommonName: proxyNames[0]}}),
		"IP name":             csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}),
		"URI name":            csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, URIs: []*url.URL{{Scheme: "spiffe", Host: "x"}}}),
		"email name":          csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, EmailAddresses: []string{"a@b.c"}}),
		"common name outside": csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, Subject: pkix.Name{CommonName: "vault.example.com"}}),
		"duplicate name":      csrPEM(t, key, x509.CertificateRequest{DNSNames: []string{proxyNames[0], proxyNames[0]}}),
		"P-384 key":           csrPEM(t, p384, x509.CertificateRequest{DNSNames: proxyNames}),
		"RSA key":             csrPEM(t, rsaKey, x509.CertificateRequest{DNSNames: proxyNames}),
		"bad signature":       string(tampered),
		"asks to be a CA":     csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{ext(t, oidBasicConstraints, basicConstraints{IsCA: true})}}),
		"basic constraints":   csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{ext(t, oidBasicConstraints, basicConstraints{})}}),
		"client auth":         csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{ext(t, oidExtKeyUsage, []asn1.ObjectIdentifier{oidServerAuth, {1, 3, 6, 1, 5, 5, 7, 3, 2}})}}),
		"cert sign usage":     csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{ext(t, oidKeyUsage, keyUsage(0, 5))}}),
		"unknown extension":   csrPEM(t, key, x509.CertificateRequest{DNSNames: proxyNames, ExtraExtensions: []pkix.Extension{ext(t, asn1.ObjectIdentifier{1, 2, 3, 4}, "x")}}),
		"trailing block":      good + good,
		"not a request":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})),
		"oversized":           good + strings.Repeat(" ", maxCSRBytes),
		"empty":               "",
	} {
		if _, err := CheckRequest(csr, proxyNames); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeSigner stands in for Vault PKI: it signs the request with a test CA,
// or, with wrong set, issues a leaf that is not the one asked for.
type fakeSigner struct {
	names  []string
	err    error
	wrong  string
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	issued string
}

func newSigner(t *testing.T) *fakeSigner {
	t.Helper()
	key := p256(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &fakeSigner{caKey: key, caCert: ca}
}

func (f *fakeSigner) SignCertificate(_ context.Context, mount, role, csrText string, names []string, ttl time.Duration) (string, string, error) {
	if mount != "pki-gatehouse-proxy" || role != "proxy" || ttl != 24*time.Hour {
		return "", "", errors.New("wrong settings")
	}
	f.names = names
	if f.err != nil {
		return "", "", f.err
	}
	block, _ := pem.Decode([]byte(csrText))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", err
	}
	public := csr.PublicKey
	leaf := &x509.Certificate{SerialNumber: new(big.Int).SetBytes([]byte{0x7f, 0x00, 0xaa, 0x01}), DNSNames: names,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ttl).Truncate(time.Second),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	switch f.wrong {
	case "ca":
		leaf.IsCA, leaf.BasicConstraintsValid, leaf.KeyUsage = true, true, x509.KeyUsageCertSign
	case "names":
		leaf.DNSNames = append([]string{"vault.example.com"}, names...)
	case "key":
		public = &f.caKey.PublicKey
	case "client":
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, public, f.caKey)
	if err != nil {
		return "", "", err
	}
	f.issued = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return f.issued, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})), nil
}

type fakeAudit struct {
	admit, record error
	events        []auditchain.Event
}

func (f *fakeAudit) Admit() error { return f.admit }

func (f *fakeAudit) Record(e auditchain.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if f.record != nil {
		return f.record
	}
	f.events = append(f.events, e)
	return nil
}

type fakeVerifier struct {
	peer netip.Addr
	err  error
}

func (f *fakeVerifier) VerifyProxy(_ context.Context, token string, peer netip.Addr) error {
	f.peer = peer
	if token != "proxy-token" {
		return errors.New("not a proxy")
	}
	return f.err
}

func TestHandlerIssuesOnlyToTheProxy(t *testing.T) {
	csr := csrPEM(t, p256(t), x509.CertificateRequest{DNSNames: proxyNames})
	body := func(csr string) *bytes.Reader {
		b, _ := json.Marshal(map[string]string{"csr": csr})
		return bytes.NewReader(b)
	}
	for name, tc := range map[string]struct {
		token    string
		csr      string
		verifier error
		signer   error
		wrong    string
		audit    fakeAudit
		status   int
	}{
		"issued":                 {"proxy-token", csr, nil, nil, "", fakeAudit{}, http.StatusOK},
		"no token":               {"", csr, nil, nil, "", fakeAudit{}, http.StatusUnauthorized},
		"not the proxy":          {"agent-token", csr, nil, nil, "", fakeAudit{}, http.StatusForbidden},
		"outside its range":      {"proxy-token", csr, errors.New("source"), nil, "", fakeAudit{}, http.StatusForbidden},
		"foreign name":           {"proxy-token", csrPEM(t, p256(t), x509.CertificateRequest{DNSNames: []string{"vault.example.com"}}), nil, nil, "", fakeAudit{}, http.StatusBadRequest},
		"vault refuses":          {"proxy-token", csr, nil, errors.New("vault"), "", fakeAudit{}, http.StatusServiceUnavailable},
		"audit not admitting":    {"proxy-token", csr, nil, nil, "", fakeAudit{admit: errors.New("overdue")}, http.StatusServiceUnavailable},
		"audit row fails":        {"proxy-token", csr, nil, nil, "", fakeAudit{record: errors.New("down")}, http.StatusServiceUnavailable},
		"vault issues a CA":      {"proxy-token", csr, nil, nil, "ca", fakeAudit{}, http.StatusBadGateway},
		"vault adds a name":      {"proxy-token", csr, nil, nil, "names", fakeAudit{}, http.StatusBadGateway},
		"vault signs other key":  {"proxy-token", csr, nil, nil, "key", fakeAudit{}, http.StatusBadGateway},
		"vault adds client auth": {"proxy-token", csr, nil, nil, "client", fakeAudit{}, http.StatusBadGateway},
	} {
		signer, verifier, audit := newSigner(t), &fakeVerifier{err: tc.verifier}, &tc.audit
		signer.err, signer.wrong = tc.signer, tc.wrong
		issuer := &Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: signer, Verifier: verifier, Audit: audit}
		if err := issuer.Validate(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/proxy/certificate", body(tc.csr))
		req.RemoteAddr = "10.200.0.7:51000"
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		issuer.Handler().ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tc.status)
			continue
		}
		if tc.status == http.StatusOK {
			var got response
			if json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Certificate != signer.issued || !strings.Contains(got.Chain, "CERTIFICATE") {
				t.Errorf("%s: body %q", name, rec.Body.String())
			}
			if len(signer.names) != 2 || verifier.peer != netip.MustParseAddr("10.200.0.7") {
				t.Errorf("%s: signed %v for peer %v", name, signer.names, verifier.peer)
			}
			want := auditchain.Event{Event: auditchain.EventCertificate, Outcome: "issued", Peer: "10.200.0.7", Serial: "7f00aa01",
				NotAfter: time.Now().Add(24 * time.Hour).Truncate(time.Second).UTC().Format(time.RFC3339)}
			if len(audit.events) != 1 || audit.events[0].Serial != want.Serial || audit.events[0].Peer != want.Peer || audit.events[0].Event != want.Event {
				t.Errorf("%s: audit %+v", name, audit.events)
			}
			if _, err := time.Parse(time.RFC3339, audit.events[0].NotAfter); err != nil {
				t.Errorf("%s: notAfter %q", name, audit.events[0].NotAfter)
			}
		}
		if tc.status != http.StatusOK && (strings.Contains(rec.Body.String(), "CERTIFICATE") || len(audit.events) != 0) {
			t.Errorf("%s: a refusal carried a certificate or an issued row", name)
		}
	}
	// Only POST to the one path is served.
	issuer := &Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: newSigner(t), Verifier: &fakeVerifier{}, Audit: &fakeAudit{}}
	for _, r := range []*http.Request{httptest.NewRequest(http.MethodGet, "/v1/proxy/certificate", nil), httptest.NewRequest(http.MethodPost, "/v1/vaults", body(csr))} {
		r.Header.Set("Authorization", "Bearer proxy-token")
		rec := httptest.NewRecorder()
		issuer.Handler().ServeHTTP(rec, r)
		if rec.Code == http.StatusOK {
			t.Errorf("%s %s served", r.Method, r.URL.Path)
		}
	}
}

func TestIssuerValidate(t *testing.T) {
	base := Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: &fakeSigner{}, Verifier: &fakeVerifier{}, Audit: &fakeAudit{}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Issuer){
		"no mount":      func(i *Issuer) { i.Mount = "" },
		"no names":      func(i *Issuer) { i.Names = nil },
		"wildcard name": func(i *Issuer) { i.Names = []string{"*.svc"} },
		"upper case":    func(i *Issuer) { i.Names = []string{"Proxy.svc"} },
		"TTL too long":  func(i *Issuer) { i.TTL = 48 * time.Hour },
		"TTL too short": func(i *Issuer) { i.TTL = time.Minute },
		"no verifier":   func(i *Issuer) { i.Verifier = nil },
		"no audit":      func(i *Issuer) { i.Audit = nil },
	} {
		i := base
		mutate(&i)
		if i.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

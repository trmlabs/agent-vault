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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
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

type fakeSigner struct {
	names []string
	err   error
}

func (f *fakeSigner) SignCertificate(_ context.Context, mount, role, _ string, names []string, ttl time.Duration) (string, string, error) {
	if mount != "pki-gatehouse-proxy" || role != "proxy" || ttl != 24*time.Hour {
		return "", "", errors.New("wrong settings")
	}
	f.names = names
	return "CERT\n", "CHAIN\n", f.err
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
		status   int
	}{
		"issued":            {"proxy-token", csr, nil, nil, http.StatusOK},
		"no token":          {"", csr, nil, nil, http.StatusUnauthorized},
		"not the proxy":     {"agent-token", csr, nil, nil, http.StatusForbidden},
		"outside its range": {"proxy-token", csr, errors.New("source"), nil, http.StatusForbidden},
		"foreign name":      {"proxy-token", csrPEM(t, p256(t), x509.CertificateRequest{DNSNames: []string{"vault.example.com"}}), nil, nil, http.StatusBadRequest},
		"vault refuses":     {"proxy-token", csr, nil, errors.New("vault"), http.StatusServiceUnavailable},
	} {
		signer, verifier := &fakeSigner{err: tc.signer}, &fakeVerifier{err: tc.verifier}
		issuer := &Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: signer, Verifier: verifier}
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
			if json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Certificate != "CERT\n" || got.Chain != "CHAIN\n" {
				t.Errorf("%s: body %q", name, rec.Body.String())
			}
			if len(signer.names) != 2 || verifier.peer != netip.MustParseAddr("10.200.0.7") {
				t.Errorf("%s: signed %v for peer %v", name, signer.names, verifier.peer)
			}
		}
		if tc.status != http.StatusOK && strings.Contains(rec.Body.String(), "CERT") {
			t.Errorf("%s: a refusal carried a certificate", name)
		}
	}
	// Only POST to the one path is served.
	issuer := &Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: &fakeSigner{}, Verifier: &fakeVerifier{}}
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
	base := Issuer{Mount: "pki-gatehouse-proxy", Role: "proxy", Names: proxyNames, TTL: 24 * time.Hour, Signer: &fakeSigner{}, Verifier: &fakeVerifier{}}
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
	} {
		i := base
		mutate(&i)
		if i.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

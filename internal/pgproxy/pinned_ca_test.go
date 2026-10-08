package pgproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testCert is a certificate and its key, signed by parent (or by itself).
type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (c testCert) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}))
}

func (c testCert) serverTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.der}, PrivateKey: c.key}}, MinVersion: tls.VersionTLS12}
}

func issue(t *testing.T, tmpl *x509.Certificate, parent *testCert) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{der: der, cert: cert, key: key}
}

func testCA(t *testing.T, name string) testCert {
	return issue(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
}

func testLeaf(t *testing.T, ca testCert, dnsName string) testCert {
	return issue(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{dnsName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &ca)
}

// citusCert is shaped like the one Citus generates for itself: self-signed,
// CN citus-auto-ssl, no extensions, and a validity period of zero seconds.
func citusCert(t *testing.T) testCert {
	now := time.Now().Add(-24 * time.Hour)
	return issue(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "citus-auto-ssl"},
		NotBefore: now, NotAfter: now}, nil)
}

// connectPinned dials a fake upstream that asks for a cleartext password:
// connectUpstream sends it only over verified TLS, so success proves the
// certificate was verified.
func connectPinned(t *testing.T, server *tls.Config, svc DatabaseService) error {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstreamTLS(t, authCleartext, lease.Password, server)
	svc.Addr, svc.SSLMode = upstream.addr(), "verify-full"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := connectUpstream(ctx, (&net.Dialer{}).DialContext, &svc, lease, nil)
	if err == nil {
		_ = sess.conn.Close()
	}
	return err
}

// handshakeRefused is true when the TLS handshake, not something after it,
// refused the server.
func handshakeRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "upstream TLS handshake")
}

func TestPinnedCAVerifiesChainAndName(t *testing.T) {
	ca := testCA(t, "cluster-ca")
	leaf := testLeaf(t, ca, "db.internal.example")
	if err := connectPinned(t, leaf.serverTLS(), DatabaseService{CA: ca.pem(), ServerName: "db.internal.example"}); err != nil {
		t.Fatalf("certificate from the pinned CA, right name: %v", err)
	}
	if err := connectPinned(t, leaf.serverTLS(), DatabaseService{CA: ca.pem(), ServerName: "other.internal.example"}); !handshakeRefused(err) {
		t.Fatal("certificate for another name accepted")
	}
	if err := connectPinned(t, leaf.serverTLS(), DatabaseService{CA: testCA(t, "other-ca").pem(), ServerName: "db.internal.example"}); !handshakeRefused(err) {
		t.Fatal("certificate from a CA other than the pinned one accepted")
	}
	// The address is 127.0.0.1, which the certificate does not name.
	if err := connectPinned(t, leaf.serverTLS(), DatabaseService{CA: ca.pem()}); !handshakeRefused(err) {
		t.Fatal("certificate checked against no name")
	}
	// Without a pin, the system roots decide, as before.
	if err := connectPinned(t, leaf.serverTLS(), DatabaseService{ServerName: "db.internal.example"}); !handshakeRefused(err) {
		t.Fatal("unpinned connection trusted a private CA")
	}
}

func TestPinnedCAServedChain(t *testing.T) {
	root := testCA(t, "root")
	intermediate := issue(t, &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &root)
	leaf := testLeaf(t, intermediate, "db.internal.example")
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der, intermediate.der}, PrivateKey: leaf.key}}, MinVersion: tls.VersionTLS12}
	for name, pin := range map[string]string{"root": root.pem(), "intermediate": intermediate.pem()} {
		if err := connectPinned(t, server, DatabaseService{CA: pin, ServerName: "db.internal.example"}); err != nil {
			t.Errorf("pinned %s: %v", name, err)
		}
	}
}

func TestPinnedSelfSignedCertificate(t *testing.T) {
	citus := citusCert(t)
	if err := connectPinned(t, citus.serverTLS(), DatabaseService{CA: citus.pem()}); err != nil {
		t.Fatalf("pinned self-signed certificate: %v", err)
	}
	// Another server with the same fixed name and its own key is not it.
	if err := connectPinned(t, citusCert(t).serverTLS(), DatabaseService{CA: citus.pem()}); !handshakeRefused(err) {
		t.Fatal("a different self-signed certificate accepted")
	}
	if err := connectPinned(t, citus.serverTLS(), DatabaseService{}); !handshakeRefused(err) {
		t.Fatal("self-signed certificate accepted without a pin")
	}
}

func TestPinnedCARefusesBadPEM(t *testing.T) {
	for name, text := range map[string]string{
		"empty":       "\n",
		"private key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"bad DER":     "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		err := connectPinned(t, citusCert(t).serverTLS(), DatabaseService{CA: text})
		if err == nil || !strings.Contains(err.Error(), "pinned CA") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

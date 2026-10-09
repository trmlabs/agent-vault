package httpcatalog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func pemCertificate(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

// A database entry may pin its CA and name: the CA must be PEM certificates
// that are CAs or self-signed, and both need verify-full.
func TestCatalogDatabasePinnedCA(t *testing.T) {
	hour := time.Now().Add(time.Hour)
	caPEM, ca, caKey := pemCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cluster-ca"},
		NotAfter: hour, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	leafPEM, _, _ := pemCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "db"},
		NotAfter: hour, DNSNames: []string{"db.example.com"}}, ca, caKey)
	// Shaped like Citus's own: self-signed, no extensions, zero validity.
	citusPEM, _, _ := pemCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "citus-auto-ssl"}}, nil, nil)

	host := "p.abc.db.postgresbridge.com"
	entry := func(postgres map[string]any) error {
		p := map[string]any{"database": "core", "mount": "database", "role": "r-readonly"}
		for k, v := range postgres {
			p[k] = v
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse([]byte(`{"pools":[{"name":"pool-a","namespace":"agents","serviceAccount":"worker"}],"entries":[` + validEntry + `,
			{"name":"core","kind":"postgres","host":"` + host + `","pools":["pool-a"],"postgres":` + string(raw) + `}]}`))
		return err
	}
	for name, p := range map[string]map[string]any{
		"CA":                   {"ca": caPEM},
		"CA and name":          {"ca": caPEM, "serverName": "abc.def.us-central1.alloydb-psc.goog"},
		"self-signed":          {"ca": citusPEM},
		"chain of two":         {"ca": caPEM + citusPEM},
		"name alone":           {"serverName": "db.example.com"},
		"IP name":              {"serverName": "10.1.2.3"},
		"explicit verify-full": {"ca": caPEM, "sslmode": "verify-full"},
	} {
		if err := entry(p); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, p := range map[string]map[string]any{
		"leaf from a CA":  {"ca": leafPEM},
		"private key":     {"ca": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
		"bad DER":         {"ca": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		"no PEM":          {"ca": "not a certificate"},
		"trailing text":   {"ca": caPEM + "extra"},
		"leading text":    {"ca": "note\n" + caPEM},
		"text between":    {"ca": caPEM + "note\n" + citusPEM},
		"oversized":       {"ca": strings.Repeat(caPEM, maxPinnedCABytes/len(caPEM)+1)},
		"uppercase name":  {"serverName": "DB.example.com"},
		"bare label name": {"serverName": "db"},
		"name with port":  {"serverName": "db.example.com:5432"},
	} {
		if err := entry(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Neither the PEM text nor its decoded value ("secret") may be echoed.
	if err := entry(map[string]any{"ca": "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"}); err == nil ||
		strings.Contains(err.Error(), "c2VjcmV0") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("a private key must be refused without echoing it: %v", err)
	}
	// The test harness's plaintext database may not carry a pin it never checks.
	plaintextDatabases.Store(true)
	t.Cleanup(func() { plaintextDatabases.Store(false) })
	host = "fixture-db.gatehouse.svc.cluster.local"
	if err := entry(map[string]any{"sslmode": "disable"}); err != nil {
		t.Fatalf("plaintext fixture refused: %v", err)
	}
	for _, p := range []map[string]any{{"sslmode": "disable", "ca": caPEM}, {"sslmode": "disable", "serverName": "db.example.com"}} {
		if err := entry(p); err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("%v: %v", p["serverName"], err)
		}
	}
}

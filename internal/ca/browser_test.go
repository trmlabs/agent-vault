package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parsePEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func spkiHash(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// The browser CA is an intermediate under the root that may sign leaves
// only, and every replica sharing the root derives the same key, so one pin
// covers the fleet. A different root gives a different browser CA.
func TestBrowserCA_DerivedFromRoot(t *testing.T) {
	dir := t.TempDir()
	first, err := New(testMasterKey(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(testMasterKey(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	other := newTestCA(t, Options{})
	b1, b2, b3 := parsePEM(t, first.BrowserCAPEM()), parsePEM(t, second.BrowserCAPEM()), parsePEM(t, other.BrowserCAPEM())
	if spkiHash(b1) != spkiHash(b2) {
		t.Fatal("replicas sharing a root derived different browser CA keys")
	}
	if spkiHash(b1) == spkiHash(b3) {
		t.Fatal("different roots derived the same browser CA key")
	}
	root := parsePEM(t, first.RootPEM())
	if spkiHash(b1) == spkiHash(root) {
		t.Fatal("the browser CA reuses the root key")
	}
	if !b1.IsCA || b1.MaxPathLen != 0 || !b1.MaxPathLenZero || b1.Subject.CommonName != BrowserCommonName ||
		!bytes.Equal(b1.RawIssuer, root.RawSubject) || b1.CheckSignatureFrom(root) != nil {
		t.Fatalf("browser CA: CA=%v pathlen=%d zero=%v cn=%q", b1.IsCA, b1.MaxPathLen, b1.MaxPathLenZero, b1.Subject.CommonName)
	}
}

// A browser leaf names its host alone, chains leaf, browser CA, root, and
// verifies through the browser CA. A pin on the browser CA matches it; an
// ordinary leaf's chain never carries the browser CA, so the pin refuses it.
func TestMintBrowserLeaf_ChainAndPin(t *testing.T) {
	c := newTestCA(t, Options{ExtraSANs: []string{"gatehouse.example", "10.0.0.1"}})
	leaf, err := c.MintBrowserLeaf("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) != 3 {
		t.Fatalf("chain length %d, want leaf, browser CA, root", len(leaf.Certificate))
	}
	browser, root := parsePEM(t, c.BrowserCAPEM()), parsePEM(t, c.RootPEM())
	if !bytes.Equal(leaf.Certificate[1], browser.Raw) || !bytes.Equal(leaf.Certificate[2], root.Raw) {
		t.Fatal("chain is not leaf, browser CA, root")
	}
	if got := leaf.Leaf.DNSNames; len(got) != 1 || got[0] != "app.example.com" || len(leaf.Leaf.IPAddresses) != 0 {
		t.Fatalf("browser leaf names %v %v, want the host alone", got, leaf.Leaf.IPAddresses)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(browser)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "app.example.com"}); err != nil {
		t.Fatalf("browser leaf does not verify: %v", err)
	}
	pin := spkiHash(browser)
	carries := func(chain [][]byte) bool {
		for _, der := range chain {
			cert, err := x509.ParseCertificate(der)
			if err == nil && spkiHash(cert) == pin {
				return true
			}
		}
		return false
	}
	ordinary, err := c.MintLeaf("github.com")
	if err != nil {
		t.Fatal(err)
	}
	if !carries(leaf.Certificate) || carries(ordinary.Certificate) {
		t.Fatal("the browser CA pin must match browser leaves and only them")
	}
	again, _ := c.MintBrowserLeaf("APP.example.com")
	if again != leaf {
		t.Fatal("browser leaves are cached per host, ignoring case")
	}
	if same, _ := c.MintLeaf("app.example.com"); same == leaf {
		t.Fatal("an ordinary leaf for the same host must not reuse the browser leaf")
	}
	if _, err := c.MintBrowserLeaf("10.0.0.5"); err == nil {
		t.Fatal("browser leaf for an IP address")
	}
	if _, err := c.MintBrowserLeaf(""); err == nil {
		t.Fatal("browser leaf for an empty name")
	}
}

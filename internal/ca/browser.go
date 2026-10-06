package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// BrowserCommonName names the intermediate that signs leaves for web apps a
// browser uses through Gatehouse, and nothing else.
const BrowserCommonName = "Agent Vault Browser CA"

// browserKeyInfo separates the browser CA's key from every other use of the
// root key. Changing it changes the browser CA's key, and so its pin.
const browserKeyInfo = "agent-vault browser CA key v1"

// deriveBrowserCA makes the browser CA from the root: its key is derived
// from the root key, so every replica sharing the root holds the same key
// and a browser can pin it by its public key hash. It may sign leaves only
// (path length zero), for as long as the root is valid.
func deriveBrowserCA(root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	secret, err := rootKey.Bytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading root key: %w", err)
	}
	var key *ecdsa.PrivateKey
	for counter := byte(0); key == nil; counter++ {
		raw, err := hkdf.Key(sha256.New, secret, []byte{counter}, browserKeyInfo, 32)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("deriving browser CA key: %w", err)
		}
		if key, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), raw); err != nil {
			key = nil // outside the curve order; try the next counter
		}
		if counter == 255 && key == nil {
			return nil, nil, nil, errors.New("deriving browser CA key: no valid scalar")
		}
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encoding browser CA key: %w", err)
	}
	serial := sha256.Sum256(append([]byte(browserKeyInfo), spki...))
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial[:16]),
		Subject:               pkix.Name{CommonName: BrowserCommonName},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating browser CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing browser CA: %w", err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// BrowserCAPEM returns the browser CA certificate in PEM form. Replicas
// sharing a root return certificates with the same public key; the
// signature bytes differ.
func (c *SoftCA) BrowserCAPEM() []byte {
	out := make([]byte, len(c.browserPEM))
	copy(out, c.browserPEM)
	return out
}

// MintBrowserLeaf returns a leaf for sni signed by the browser CA, chained
// leaf, browser CA, root. It carries sni alone, without the extra names
// MintLeaf adds, so a browser pinning the browser CA trusts it for that
// host only. The caller decides that sni is a web app's host.
func (c *SoftCA) MintBrowserLeaf(sni string) (*tls.Certificate, error) {
	isIP, err := validateSNI(sni)
	if err != nil {
		return nil, err
	}
	if isIP {
		return nil, errors.New("browser leaves name a host, not an address")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.browserCert == nil {
		return nil, errors.New("browser CA not initialised")
	}
	key := "browser\x00" + strings.ToLower(sni)
	now := c.clock()
	if existing, ok := c.cache.get(key); ok && existing.Leaf != nil && existing.Leaf.NotAfter.After(now.Add(clockSkew)) {
		return existing, nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.browserCert, &leafKey.PublicKey, c.browserKey)
	if err != nil {
		return nil, fmt.Errorf("creating browser leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing browser leaf: %w", err)
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, c.browserCert.Raw, c.rootCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
	c.cache.add(key, tlsCert)
	return tlsCert, nil
}

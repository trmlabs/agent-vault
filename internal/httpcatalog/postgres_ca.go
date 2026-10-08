package httpcatalog

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// maxPinnedCABytes bounds a database entry's pinned CA. A chain of a few
// certificates fits many times over; the catalog is held in memory and in
// every Vault entry document.
const maxPinnedCABytes = 32 << 10

// validPinnedCA accepts PEM CERTIFICATE blocks and nothing else, at least one.
// Each must be a CA certificate or self-signed: pinning a leaf some other CA
// issued would trust nothing the handshake can check.
func validPinnedCA(text string) error {
	if len(text) > maxPinnedCABytes {
		return fmt.Errorf("postgres ca is over %d bytes", maxPinnedCABytes)
	}
	rest := []byte(text)
	count := 0
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			// Never echo the block: a pasted private key must not reach a log.
			return errors.New("postgres ca holds a PEM block that is not a CERTIFICATE")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("postgres ca certificate %d: %w", count+1, err)
		}
		if (!cert.BasicConstraintsValid || !cert.IsCA) && !selfSigned(cert) {
			return fmt.Errorf("postgres ca certificate %d (%s) is neither a CA nor self-signed", count+1, cert.Subject)
		}
		count++
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return errors.New("postgres ca has text that is not a PEM certificate")
	}
	if count == 0 {
		return errors.New("postgres ca has no PEM certificate")
	}
	return nil
}

// selfSigned checks the signature against the certificate's own key without
// CheckSignatureFrom's CA constraint: Citus's generated certificate carries
// no extensions at all.
func selfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

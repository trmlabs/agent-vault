// Package proxycert issues the serving certificate a shared proxy in another
// cluster presents to its agent sandboxes, so the hop from a sandbox to its
// proxy is encrypted and the sandbox can verify it. The proxy keeps its key in
// memory and sends only a certificate request; the broker checks that the
// caller is a proxy identity and that the request names only the proxy's own
// service names, then a Vault PKI role restricted to those names signs it.
package proxycert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// Signer signs a request for exactly names; Vault's PKI engine in production.
type Signer interface {
	SignCertificate(ctx context.Context, mount, role, csrPEM string, names []string, ttl time.Duration) (string, string, error)
}

// ProxyVerifier admits only a shared proxy's own identity, from its token and
// the connection's source address.
type ProxyVerifier interface {
	VerifyProxy(ctx context.Context, token string, peer netip.Addr) error
}

// Audit is the signed audit trail: Admit refuses while it cannot record, and
// Record must succeed before a certificate is handed out.
type Audit interface {
	Admit() error
	Record(auditchain.Event) error
}

// Issuer holds the settings for proxy serving certificates.
type Issuer struct {
	Mount, Role string
	Names       []string // the only DNS names a certificate may carry
	TTL         time.Duration
	Signer      Signer
	Verifier    ProxyVerifier
	Audit       Audit
	Logger      *slog.Logger
}

const (
	// The request and CSR bounds only stop an oversized body; a CSR naming
	// every DNS name the broker allows fits well inside them.
	maxRequestBytes = 1 << 20
	maxCSRBytes     = 512 << 10
	// MaxTTL bounds a proxy certificate. A proxy renews at two thirds of it.
	MaxTTL = 24 * time.Hour
)

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Validate checks the settings at startup.
func (i *Issuer) Validate() error {
	if i.Mount == "" || i.Role == "" || i.Signer == nil || i.Verifier == nil {
		return errors.New("proxy certificates need a Vault PKI mount and role")
	}
	if i.Audit == nil {
		return errors.New("proxy certificates need the signed audit trail")
	}
	if len(i.Names) == 0 {
		return errors.New("proxy certificates need at least one DNS name")
	}
	for _, name := range i.Names {
		if len(name) > 253 || !dnsName.MatchString(name) {
			return errors.New("proxy certificate names must be lower-case DNS names")
		}
	}
	if i.TTL < time.Hour || i.TTL > MaxTTL {
		return errors.New("proxy certificate TTL must be between one hour and 24 hours")
	}
	return nil
}

var (
	errCSR    = errors.New("certificate request refused")
	errIssued = errors.New("issued certificate is not the one requested")
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
)

// CheckRequest parses a PEM certificate request and refuses anything but an
// ECDSA P-256 key, a valid self-signature and DNS names that are all in
// allowed, with no IP, URI or email names. The only extensions it may ask for
// are subject alternative names, server authentication as its sole extended
// key usage, and key usage limited to digital signature and key agreement,
// so it cannot ask to be a CA. It returns the names to sign.
func CheckRequest(csrPEM string, allowed []string) ([]string, error) {
	if len(csrPEM) > maxCSRBytes {
		return nil, errCSR
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errCSR
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errCSR
	}
	if len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 || len(csr.DNSNames) == 0 {
		return nil, errCSR
	}
	if !requestedExtensionsAllowed(csr) {
		return nil, errCSR
	}
	permitted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		permitted[name] = true
	}
	names := make([]string, 0, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		if !permitted[name] {
			return nil, errCSR
		}
		permitted[name] = false // each name once
		names = append(names, name)
	}
	if cn := csr.Subject.CommonName; cn != "" && !slices.Contains(names, cn) {
		return nil, errCSR
	}
	return names, nil
}

func requestedExtensionsAllowed(csr *x509.CertificateRequest) bool {
	seen := map[string]bool{}
	for _, ext := range csr.Extensions {
		id := ext.Id.String()
		if seen[id] {
			return false
		}
		seen[id] = true
		switch {
		case ext.Id.Equal(oidSubjectAltName):
		case ext.Id.Equal(oidExtKeyUsage):
			var usages []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(ext.Value, &usages); err != nil || len(rest) != 0 || len(usages) != 1 || !usages[0].Equal(oidServerAuth) {
				return false
			}
		case ext.Id.Equal(oidKeyUsage):
			var bits asn1.BitString
			if rest, err := asn1.Unmarshal(ext.Value, &bits); err != nil || len(rest) != 0 {
				return false
			}
			for bit := range bits.BitLength {
				// 0 is digitalSignature and 4 keyAgreement; 5 keyCertSign
				// and 6 cRLSign are the ones a proxy must never hold.
				if bits.At(bit) == 1 && bit != 0 && bit != 4 {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// checkIssued parses what Vault signed and confirms it is the leaf asked for:
// for the request's key, exactly names, server authentication only and not a
// CA. It returns the serial in lower-case hex and notAfter in RFC 3339 UTC.
func checkIssued(certificatePEM string, csrPEM string, names []string) (string, string, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", "", errIssued
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", errIssued
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return "", "", errIssued
	}
	want, _ := csr.PublicKey.(*ecdsa.PublicKey)
	got, _ := leaf.PublicKey.(*ecdsa.PublicKey)
	if want == nil || got == nil || !want.Equal(got) || leaf.IsCA || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 ||
		!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 ||
		!slices.Equal(slices.Sorted(slices.Values(leaf.DNSNames)), slices.Sorted(slices.Values(names))) || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() < 0 {
		return "", "", errIssued
	}
	return hex.EncodeToString(leaf.SerialNumber.Bytes()), leaf.NotAfter.UTC().Format(time.RFC3339), nil
}

type request struct {
	CSR string `json:"csr"`
}

type response struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
}

// Handler serves POST /v1/proxy/certificate. The proxy authenticates with its
// own token as a bearer credential; the peer address is the one the TLS front
// reported. Every refusal is generic to the caller and named in the log.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	i.Register(mux)
	return mux
}

// Register adds the certificate route to mux.
func (i *Issuer) Register(mux *http.ServeMux) { mux.HandleFunc("POST /v1/proxy/certificate", i.serve) }

func (i *Issuer) serve(w http.ResponseWriter, r *http.Request) {
	refuse := func(status int, reason string) {
		i.log().Warn("proxycert: certificate refused", "reason", reason)
		http.Error(w, http.StatusText(status), status)
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		refuse(http.StatusUnauthorized, "no_token")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, perr := netip.ParseAddr(host)
	if err != nil || perr != nil {
		refuse(http.StatusForbidden, "peer")
		return
	}
	peer = peer.Unmap()
	if err := i.Verifier.VerifyProxy(r.Context(), token, peer); err != nil {
		refuse(http.StatusForbidden, "not_proxy")
		return
	}
	if i.Audit.Admit() != nil {
		refuse(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	var body request
	d := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil {
		refuse(http.StatusBadRequest, "body")
		return
	}
	names, err := CheckRequest(body.CSR, i.Names)
	if err != nil {
		refuse(http.StatusBadRequest, "csr")
		return
	}
	certificate, chain, err := i.Signer.SignCertificate(r.Context(), i.Mount, i.Role, body.CSR, names, i.TTL)
	if err != nil {
		refuse(http.StatusServiceUnavailable, "signing")
		return
	}
	serial, notAfter, err := checkIssued(certificate, body.CSR, names)
	if err != nil {
		refuse(http.StatusBadGateway, "issued_mismatch")
		return
	}
	// The certificate goes out only once its row is in the signed trail.
	if i.Audit.Record(auditchain.Event{Event: auditchain.EventCertificate, Outcome: "issued", Peer: peer.String(), Serial: serial, NotAfter: notAfter}) != nil {
		refuse(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	i.log().Info("proxycert: certificate issued", "names", strings.Join(names, ","), "serial", serial, "not_after", notAfter)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{Certificate: certificate, Chain: chain})
}

func (i *Issuer) log() *slog.Logger {
	if i.Logger != nil {
		return i.Logger
	}
	return slog.Default()
}

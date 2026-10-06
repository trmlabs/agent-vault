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

// Issuer holds the settings for proxy serving certificates.
type Issuer struct {
	Mount, Role string
	Names       []string // the only DNS names a certificate may carry
	TTL         time.Duration
	Signer      Signer
	Verifier    ProxyVerifier
	Logger      *slog.Logger
}

const (
	maxRequestBytes = 16 << 10
	maxCSRBytes     = 8 << 10
	// MaxTTL bounds a proxy certificate. A proxy renews at two thirds of it.
	MaxTTL = 24 * time.Hour
)

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Validate checks the settings at startup.
func (i *Issuer) Validate() error {
	if i.Mount == "" || i.Role == "" || i.Signer == nil || i.Verifier == nil {
		return errors.New("proxy certificates need a Vault PKI mount and role")
	}
	if len(i.Names) == 0 || len(i.Names) > 8 {
		return errors.New("proxy certificates need 1 to 8 DNS names")
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
	errCSR = errors.New("certificate request refused")
)

// CheckRequest parses a PEM certificate request and refuses anything but an
// ECDSA P-256 key, a valid self-signature and DNS names that are all in
// allowed, with no IP, URI or email names. It returns the names to sign.
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
	var names []string
	for _, name := range csr.DNSNames {
		if !slices.Contains(allowed, name) || slices.Contains(names, name) {
			return nil, errCSR
		}
		names = append(names, name)
	}
	if cn := csr.Subject.CommonName; cn != "" && !slices.Contains(names, cn) {
		return nil, errCSR
	}
	return names, nil
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
	mux.HandleFunc("POST /v1/proxy/certificate", i.serve)
	return mux
}

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
	if err := i.Verifier.VerifyProxy(r.Context(), token, peer.Unmap()); err != nil {
		refuse(http.StatusForbidden, "not_proxy")
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
	i.log().Info("proxycert: certificate issued", "names", strings.Join(names, ","), "ttl", i.TTL.String())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{Certificate: certificate, Chain: chain})
}

func (i *Issuer) log() *slog.Logger {
	if i.Logger != nil {
		return i.Logger
	}
	return slog.Default()
}

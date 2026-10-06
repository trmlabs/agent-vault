package taskrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"
)

// ServingTLSConfig, in shared mode only, encrypts the hop from each agent Pod
// to this proxy with a certificate the broker issues. Mode "broker-issued" is
// the only mode. Names are the proxy Service's DNS names; the broker signs
// only names it was configured with.
type ServingTLSConfig struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names"`
}

const brokerIssued = "broker-issued"

// waitingLogInterval spaces the "still no certificate" rows at startup.
var waitingLogInterval = time.Minute

// ProxyCertificatePath is the broker's issuing route on its cross-cluster
// listener.
const ProxyCertificatePath = "/v1/proxy/certificate"

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func (s *ServingTLSConfig) validate() error {
	if s.Mode != brokerIssued || len(s.Names) == 0 {
		return errConfig
	}
	for i, name := range s.Names {
		if len(name) > 253 || !dnsName.MatchString(name) || slices.Contains(s.Names[:i], name) {
			return errConfig
		}
	}
	return nil
}

var errNoServingCertificate = errors.New("no current serving certificate")

// servingCert holds the proxy's serving certificate. Its key is generated in
// memory for each certificate and never written anywhere; only a certificate
// request leaves the process. A certificate is renewed at two thirds of its
// lifetime, the old one serves until the new one arrives, and once it expires
// with no replacement every handshake is refused.
type servingCert struct {
	names    []string
	upstream UpstreamConfig
	issued   func(issued, notAfter time.Time) // for the audit; may be nil
	// waiting is called once a minute while the first certificate has not
	// arrived: with no readiness probe the proxy looks ready meanwhile, so
	// the log must say it is serving nothing. May be nil.
	waiting func()

	mu        sync.RWMutex
	current   *tls.Certificate
	notBefore time.Time
	notAfter  time.Time
}

func newServingCert(s *ServingTLSConfig, upstream UpstreamConfig) *servingCert {
	return &servingCert{names: slices.Clone(s.Names), upstream: upstream}
}

// get is tls.Config.GetCertificate.
func (s *servingCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil || !time.Now().Before(s.notAfter) {
		return nil, errNoServingCertificate
	}
	return s.current, nil
}

func (s *servingCert) serverTLS(protocols ...string) *tls.Config {
	return &tls.Config{GetCertificate: s.get, MinVersion: tls.VersionTLS12, NextProtos: protocols}
}

// renewAt is two thirds of the way through the current certificate's life.
func (s *servingCert) renewAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.notBefore.Add(s.notAfter.Sub(s.notBefore) * 2 / 3)
}

func (s *servingCert) expiry() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.notAfter
}

// obtain retries the first issuance with backoff until it succeeds or ctx
// ends: the proxy serves nothing without a certificate.
func (s *servingCert) obtain(ctx context.Context) error {
	wait := time.Second
	logged := time.Now()
	for {
		if s.renew(ctx) == nil {
			return nil
		}
		if s.waiting != nil && time.Since(logged) >= waitingLogInterval {
			s.waiting()
			logged = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Minute)
	}
}

// run renews until ctx ends. A failed renewal is retried, sooner as expiry
// nears, and the current certificate keeps serving meanwhile.
func (s *servingCert) run(ctx context.Context) {
	next := s.renewAt()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		if s.renew(ctx) == nil {
			next = s.renewAt()
			continue
		}
		next = time.Now().Add(min(5*time.Minute, max(time.Second, time.Until(s.expiry())/4)))
	}
}

// renew asks the broker for a certificate on a new key and installs it.
func (s *servingCert) renew(ctx context.Context) error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: s.names[0]}, DNSNames: s.names}, key)
	if e != nil {
		return e
	}
	body, e := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if e != nil {
		return e
	}
	token, _, e := readProjectedProof(s.upstream)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, e := dialUpstream(ctx, s.upstream)
	if e != nil {
		return e
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.upstream.ServerName+ProxyCertificatePath, bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	if e = req.Write(conn); e != nil {
		return e
	}
	resp, e := http.ReadResponse(bufio.NewReader(conn), req)
	if e != nil {
		return e
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errDenied
	}
	var issued struct {
		Certificate string `json:"certificate"`
		Chain       string `json:"chain"`
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 256<<10))
	d.DisallowUnknownFields()
	if d.Decode(&issued) != nil {
		return errDenied
	}
	cert, leaf, e := s.check(key, issued.Certificate, issued.Chain, time.Now())
	if e != nil {
		return e
	}
	s.mu.Lock()
	s.current, s.notBefore, s.notAfter = cert, leaf.NotBefore, leaf.NotAfter
	s.mu.Unlock()
	if s.issued != nil {
		s.issued(leaf.NotBefore, leaf.NotAfter)
	}
	return nil
}

// check accepts only a current leaf for this key that names nothing beyond
// the configured names and is for server authentication.
func (s *servingCert) check(key *ecdsa.PrivateKey, certificate, chain string, now time.Time) (*tls.Certificate, *x509.Certificate, error) {
	var ders [][]byte
	for _, text := range []string{certificate, chain} {
		rest := []byte(text)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, nil, errDenied
			}
			ders = append(ders, block.Bytes)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, errDenied
		}
	}
	if len(ders) == 0 {
		return nil, nil, errDenied
	}
	leaf, e := x509.ParseCertificate(ders[0])
	if e != nil {
		return nil, nil, errDenied
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(key.Public()) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		len(leaf.DNSNames) == 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, nil, errDenied
	}
	for _, name := range leaf.DNSNames {
		if !slices.Contains(s.names, name) {
			return nil, nil, errDenied
		}
	}
	if len(leaf.ExtKeyUsage) != 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return nil, nil, errDenied
	}
	// Vault returns the issuing chain beside the leaf; a repeat of the leaf
	// in it is dropped.
	chainDERs := [][]byte{ders[0]}
	for _, der := range ders[1:] {
		if !bytes.Equal(der, ders[0]) {
			chainDERs = append(chainDERs, der)
		}
	}
	return &tls.Certificate{Certificate: chainDERs, PrivateKey: key, Leaf: leaf}, leaf, nil
}

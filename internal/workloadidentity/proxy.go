package workloadidentity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// ProxyBinding makes a Binding a shared proxy's: the binding's namespace,
// account and account UID name exactly one proxy service account, and the
// broker admits the agent Pods that proxy attests, within these limits. The
// proxy runs the Pod check in its own cluster (source address, live Pod,
// controller owner, images); the broker never sees the agent's address.
type ProxyBinding struct {
	// Namespaces the attested agent Pods may run in.
	Namespaces []string `json:"namespaces"`
	// OwnerKind is the controller kind that must own each agent Pod (Sandbox).
	OwnerKind string `json:"ownerKind"`
	// ImageDigests every container of an attested Pod must run.
	ImageDigests []string `json:"imageDigests"`
	// SourceCIDRs the proxy's connections must come from: the private link's
	// address range. A connection from anywhere else is refused.
	SourceCIDRs []string `json:"sourceCIDRs"`
	// MaxSessionSeconds caps a session from the proxy token's issue time (60 s
	// to 8 h). A remote proxy token cannot be revoked by a live Pod read, so
	// this bounds how long an open session outlives it.
	MaxSessionSeconds int64 `json:"maxSessionSeconds"`
}

// Attestation is what a shared proxy states about the agent Pod behind one
// connection. It is trusted only from the proxy binding's own authenticated
// account, on the same connection as that account's token.
type Attestation struct {
	Namespace    string   `json:"namespace"`
	PodName      string   `json:"podName"`
	PodUID       string   `json:"podUID"`
	OwnerKind    string   `json:"ownerKind"`
	OwnerUID     string   `json:"ownerUID"` // the controller object, such as the Sandbox
	ImageDigests []string `json:"imageDigests"`
	NotAfter     int64    `json:"notAfter"` // Unix seconds: when the agent's admission ends
}

const maxAttestationBytes = 4096

var (
	kubernetesKind = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	objectUID      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)
)

// EncodeAttestation is the wire form: unpadded base64url JSON, safe in an
// HTTP header and a PostgreSQL preamble line.
func EncodeAttestation(a Attestation) (string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) > maxAttestationBytes {
		return "", errors.New("attestation too large")
	}
	return s, nil
}

func decodeAttestation(s string) (Attestation, error) {
	var a Attestation
	if s == "" || len(s) > maxAttestationBytes {
		return a, errors.New("invalid attestation")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return a, errors.New("invalid attestation")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF {
		return a, errors.New("invalid attestation")
	}
	if !pathSegment(a.Namespace) || !pathSegment(a.PodName) || !objectUID.MatchString(a.PodUID) || !kubernetesKind.MatchString(a.OwnerKind) ||
		!objectUID.MatchString(a.OwnerUID) || len(a.ImageDigests) == 0 || len(a.ImageDigests) > 32 || a.NotAfter <= 0 {
		return a, errors.New("invalid attestation")
	}
	return a, nil
}

// validate checks a proxy binding at load.
func (p *ProxyBinding) validate() error {
	if len(p.Namespaces) == 0 || len(p.Namespaces) > 16 {
		return errors.New("proxy binding needs 1 to 16 agent namespaces")
	}
	for _, ns := range p.Namespaces {
		if !pathSegment(ns) {
			return errors.New("proxy binding namespace must be a DNS-style name")
		}
	}
	if !kubernetesKind.MatchString(p.OwnerKind) {
		return errors.New("proxy binding needs the agent Pods' controller kind")
	}
	if len(p.ImageDigests) == 0 || len(p.ImageDigests) > 16 {
		return errors.New("proxy binding requires 1 to 16 image digests")
	}
	for _, digest := range p.ImageDigests {
		if !imageDigest.MatchString(digest) {
			return errors.New("proxy binding image digest must be sha256: and 64 lowercase hex characters")
		}
	}
	if len(p.SourceCIDRs) == 0 || len(p.SourceCIDRs) > 16 {
		return errors.New("proxy binding needs 1 to 16 source ranges")
	}
	for _, cidr := range p.SourceCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return errors.New("proxy binding source range must be a non-default CIDR")
		}
	}
	if p.MaxSessionSeconds < 60 || p.MaxSessionSeconds > 8*3600 {
		return errors.New("proxy binding maxSessionSeconds must be between 60 and 28800")
	}
	return nil
}

func (p *ProxyBinding) fromSource(peer netip.Addr) bool {
	for _, cidr := range p.SourceCIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(peer) {
			return true
		}
	}
	return false
}

// attestProxied admits the agent Pod a proxy attests. The proxy's token was
// verified by attest; here the connection's source, the attestation and the
// profile are checked, and the scope is the attested Pod's.
func (r *Resolver) attestProxied(ctx context.Context, binding *Binding, c claims, d *domain, peer netip.Addr, encoded string, renewal bool) (*brokercore.ProxyScope, error) {
	deny := brokercore.ErrInvalidSession
	p := binding.Proxy
	if !p.fromSource(peer) {
		return nil, deny
	}
	a, err := decodeAttestation(encoded)
	if err != nil || !slices.Contains(p.Namespaces, a.Namespace) || a.OwnerKind != p.OwnerKind {
		return nil, deny
	}
	for _, digest := range a.ImageDigests {
		if !slices.Contains(p.ImageDigests, digest) {
			return nil, deny
		}
	}
	notAfter := time.Unix(a.NotAfter, 0)
	if limit := time.Unix(c.Issued, 0).Add(time.Duration(p.MaxSessionSeconds) * time.Second); limit.Before(notAfter) {
		notAfter = limit
	}
	if !r.now().Before(notAfter) {
		return nil, deny
	}
	if !r.profileAdmits(binding.Pool, d, IdentityProxyAttested, a.Namespace, a.OwnerKind, a.ImageDigests) {
		return nil, deny
	}
	scope, err := r.grant(ctx, binding, "")
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (c.Expires <= r.now().Unix() && !renewal) || !r.now().Before(notAfter) {
		return nil, deny
	}
	scope.WorkloadID, scope.NotAfter, scope.Pool, scope.IdentityKind = a.PodUID, notAfter, binding.Pool, brokercore.KindProxyAttested
	return scope, nil
}

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
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/imagerule"
)

// ProxyBinding makes a Binding a shared proxy's: the binding's namespace,
// account and account UID name exactly one proxy service account, and the
// broker admits the agent Pods that proxy attests, within these limits. The
// proxy runs the Pod check in its own cluster (source address, live Pod,
// controller owner, images); the broker never sees the agent's address.
type ProxyBinding struct {
	// Profiles maps each namespace the proxy serves to its harness profile
	// and catalog pool. A namespace not listed is refused, so one proxy can
	// serve customer and developer sandboxes without either reaching the
	// other's entries.
	Profiles []ProxyProfile `json:"profiles"`
	// OwnerKind is the controller kind that must own each agent Pod (Sandbox).
	OwnerKind string `json:"ownerKind"`
	// ImageDigests are exact digests any attested Pod may run, for containers
	// the platform injects (such as a storage sidecar). Optional when every
	// profile names an image prefix.
	ImageDigests []string `json:"imageDigests,omitempty"`
	// SourceCIDRs the proxy's connections must come from: the private link's
	// address range. A connection from anywhere else is refused.
	SourceCIDRs []string `json:"sourceCIDRs"`
	// MaxSessionSeconds caps a session from the proxy token's issue time (60
	// to 1800 s). A remote proxy token cannot be revoked by a live Pod read,
	// so this bounds how long an open session outlives it.
	MaxSessionSeconds int64 `json:"maxSessionSeconds"`
}

// ProxyProfile is one namespace a proxy serves: the harness profile its
// attestation must name, and the catalog pool its agents are admitted into.
type ProxyProfile struct {
	Namespace string `json:"namespace"`
	Profile   string `json:"profile"`
	Pool      string `json:"pool"`
	// ImagePrefix, when set, admits any image pulled from under this
	// agent-sandbox repository path (see imagerule.ValidPrefix).
	ImagePrefix string `json:"imagePrefix,omitempty"`
}

// profileFor returns the namespace's profile, or false.
func (p *ProxyBinding) profileFor(namespace string) (ProxyProfile, bool) {
	for _, pp := range p.Profiles {
		if pp.Namespace == namespace {
			return pp, true
		}
	}
	return ProxyProfile{}, false
}

// Attestation is what a shared proxy states about the agent Pod behind one
// connection. It is trusted only from the proxy binding's own authenticated
// account, on the same connection as that account's token.
type Attestation struct {
	Namespace string `json:"namespace"`
	PodName   string `json:"podName"`
	PodUID    string `json:"podUID"`
	OwnerKind string `json:"ownerKind"`
	OwnerUID  string `json:"ownerUID"` // the controller object, such as the Sandbox
	// Images are the references every container and init container pulled
	// (repository@sha256:...), as the node reported them.
	Images   []string `json:"images"`
	NotAfter int64    `json:"notAfter"` // Unix seconds: when the agent's admission ends
	// Profile is the harness profile the proxy maps the namespace to; the
	// broker refuses it unless its own map agrees.
	Profile string `json:"profile"`
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
		!objectUID.MatchString(a.OwnerUID) || len(a.Images) == 0 || len(a.Images) > 32 || a.NotAfter <= 0 || !pathSegment(a.Profile) {
		return a, errors.New("invalid attestation")
	}
	for _, image := range a.Images {
		if _, _, ok := imagerule.Split(image); !ok {
			return a, errors.New("invalid attestation")
		}
	}
	return a, nil
}

// validate checks a proxy binding at load.
func (p *ProxyBinding) validate() error {
	if len(p.Profiles) == 0 || len(p.Profiles) > maxProxyProfiles {
		return errors.New("proxy binding needs 1 to 10,000 namespace profiles")
	}
	seen := map[string]bool{}
	for i, pp := range p.Profiles {
		if !pathSegment(pp.Namespace) || !pathSegment(pp.Profile) || !pathSegment(pp.Pool) || seen[pp.Namespace] {
			return errors.New("proxy binding profiles need a unique namespace, a profile and a pool")
		}
		seen[pp.Namespace] = true
		if pp.ImagePrefix == "" {
			if len(p.ImageDigests) == 0 {
				return errors.New("a proxy profile without an image prefix needs the binding's image digests")
			}
			continue
		}
		if !imagerule.ValidPrefix(pp.ImagePrefix) {
			return errors.New("proxy profile image prefix must be an agent-sandbox repository or tenant path")
		}
		for _, other := range p.Profiles[:i] {
			if other.ImagePrefix != "" && imagerule.Overlap(other.ImagePrefix, pp.ImagePrefix) {
				return errors.New("two proxy profiles claim overlapping image prefixes")
			}
		}
	}
	if !kubernetesKind.MatchString(p.OwnerKind) {
		return errors.New("proxy binding needs the agent Pods' controller kind")
	}
	for _, digest := range p.ImageDigests {
		if !imageDigest.MatchString(digest) {
			return errors.New("proxy binding image digest must be sha256: and 64 lowercase hex characters")
		}
	}
	if len(p.SourceCIDRs) == 0 || len(p.SourceCIDRs) > maxListItems {
		return errors.New("proxy binding needs 1 to 1,024 source ranges")
	}
	for _, cidr := range p.SourceCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return errors.New("proxy binding source range must be a non-default CIDR")
		}
	}
	if p.MaxSessionSeconds < 60 || p.MaxSessionSeconds > 1800 {
		return errors.New("proxy binding maxSessionSeconds must be between 60 and 1800")
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
	p := binding.Proxy
	if !p.fromSource(peer) {
		return nil, brokercore.Denied("proxy_source")
	}
	// A recheck may outlive the proxy token, but only by one token lifetime.
	if renewal && r.now().Unix() > c.Expires+d.maxLifetime {
		return nil, brokercore.Denied("proxy_token_expired")
	}
	a, err := decodeAttestation(encoded)
	if err != nil {
		return nil, brokercore.Denied("attestation_invalid")
	}
	if a.OwnerKind != p.OwnerKind {
		return nil, brokercore.Denied("attestation_owner_kind")
	}
	// The namespace picks the profile and pool; the proxy must name the same
	// profile, and an unlisted namespace is refused.
	profile, ok := p.profileFor(a.Namespace)
	if !ok {
		return nil, brokercore.Denied("attestation_namespace")
	}
	if a.Profile != profile.Profile {
		return nil, brokercore.Denied("attestation_profile")
	}
	for _, image := range a.Images {
		if !imagerule.Allowed(image, profile.ImagePrefix, p.ImageDigests) {
			return nil, brokercore.Denied("attestation_image")
		}
	}
	notAfter := time.Unix(a.NotAfter, 0)
	if limit := time.Unix(c.Issued, 0).Add(time.Duration(p.MaxSessionSeconds) * time.Second); limit.Before(notAfter) {
		notAfter = limit
	}
	if !r.now().Before(notAfter) {
		return nil, brokercore.Denied("deadline")
	}
	if !r.proxyProfileAdmits(profile, d, a) {
		return nil, brokercore.Denied("catalog_profile")
	}
	scope, err := r.grant(ctx, binding, "")
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (c.Expires <= r.now().Unix() && !renewal) || !r.now().Before(notAfter) {
		return nil, brokercore.Denied("deadline")
	}
	scope.WorkloadID, scope.NotAfter, scope.Pool, scope.IdentityKind = a.PodUID, notAfter, profile.Pool, brokercore.KindProxyAttested
	return scope, nil
}

// VerifyProxy admits a shared proxy itself, not an agent behind it: a current
// token from a proxy binding's own account, from the binding's source ranges.
// It is how a proxy asks the broker for its serving certificate.
func (r *Resolver) VerifyProxy(ctx context.Context, token string, peer netip.Addr) error {
	if !peer.IsValid() || peer.IsLoopback() || peer.IsUnspecified() {
		return brokercore.Denied("peer")
	}
	peer = peer.Unmap()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	c, d, err := r.verifyLocally(ctx, token, false)
	if err != nil {
		return err
	}
	k := c.Kubernetes
	for i := range r.config.Bindings {
		b := &r.config.Bindings[i]
		if b.TrustDomain == d.name && b.Namespace == k.Namespace && b.ServiceAccount == k.ServiceAccount.Name && b.ServiceAccountUID == k.ServiceAccount.UID {
			if b.Proxy == nil {
				return brokercore.Denied("not_proxy")
			}
			if !b.Proxy.fromSource(peer) {
				return brokercore.Denied("proxy_source")
			}
			return nil
		}
	}
	return brokercore.Denied("no_binding")
}

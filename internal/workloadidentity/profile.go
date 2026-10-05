package workloadidentity

import "slices"

// Identity kinds a harness profile names.
const (
	IdentityPodToken      = "pod-token"
	IdentitySessionJWT    = "session-jwt"
	IdentityProxyAttested = "proxy-attested"
)

// Profile is the identity half of a pool's declared harness profile: the
// trust domain, identity kind, namespaces, controller kind and images its
// agents must match. The broker catalog holds it, so it can change at a
// catalog reload without a restart.
type Profile struct {
	Name         string
	Issuer       string
	Audience     string
	Remote       bool
	Kind         string
	OwnerKind    string
	Namespaces   []string
	ImageDigests []string
}

// ProfileSource returns the declared profile for a pool, or false when the
// catalog declares none (its profile is then derived, and checks nothing
// beyond the binding).
type ProfileSource func(pool string) (Profile, bool)

type profileSource struct{ fn ProfileSource }

// SetProfiles makes every admission also match the pool's declared profile.
func (r *Resolver) SetProfiles(fn ProfileSource) {
	r.profiles.Store(&profileSource{fn: fn})
}

// profileAdmits reports whether an admission matches the pool's declared
// profile. A pool Pod (kind pod-token) may serve a pod-token or session-jwt
// profile: both are the Pod's own token, and the session is checked later.
func (r *Resolver) profileAdmits(pool string, d *domain, kind, namespace, ownerKind string, images []string) bool {
	src := r.profiles.Load()
	if src == nil || src.fn == nil {
		return true
	}
	p, ok := src.fn(pool)
	if !ok {
		return true
	}
	if p.Issuer != d.issuer || p.Audience != d.audience || p.Remote != d.remote {
		return false
	}
	switch kind {
	case IdentityProxyAttested:
		if p.Kind != IdentityProxyAttested {
			return false
		}
	default:
		if p.Kind != IdentityPodToken && p.Kind != IdentitySessionJWT {
			return false
		}
	}
	if !slices.Contains(p.Namespaces, namespace) || ownerKind != p.OwnerKind || len(images) == 0 {
		return false
	}
	for _, image := range images {
		if !slices.Contains(p.ImageDigests, image) {
			return false
		}
	}
	return true
}

// proxyProfileAdmits requires a declared catalog profile for a proxy
// admission: the one the binding maps the namespace to, from the trust
// domain that verified the proxy's token. With no catalog profile, the proxy
// admits nothing.
func (r *Resolver) proxyProfileAdmits(pp ProxyProfile, d *domain, a Attestation) bool {
	src := r.profiles.Load()
	if src == nil || src.fn == nil {
		return false
	}
	p, ok := src.fn(pp.Pool)
	if !ok || p.Name != pp.Profile || len(p.Namespaces) != 1 {
		return false
	}
	return r.profileAdmits(pp.Pool, d, IdentityProxyAttested, a.Namespace, a.OwnerKind, a.ImageDigests)
}

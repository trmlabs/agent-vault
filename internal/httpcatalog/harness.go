package httpcatalog

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

// Harness is one agent runtime's profile: how its agents prove who they are,
// how they reach the broker, and whether access is decided for the pool or
// for the person behind each session. A new runtime is a new entry here, and
// needs code only if it brings a new identity kind. Every field is required
// unless marked optional, and an incomplete or contradictory entry refuses
// the whole catalog.
type Harness struct {
	Name          string               `json:"name"`
	TrustDomain   HarnessTrustDomain   `json:"trustDomain"`
	Identity      HarnessIdentity      `json:"identity"`
	Path          HarnessPath          `json:"path"`
	Authorization HarnessAuthorization `json:"authorization"`
}

// HarnessTrustDomain is the cluster whose service-account tokens the broker
// accepts for this harness. Keys "in-cluster" reads the signing keys from the
// broker's own cluster API; "remote" fetches the issuer's published keys.
type HarnessTrustDomain struct {
	Issuer   string `json:"issuer"`
	Keys     string `json:"keys"`
	Audience string `json:"audience"`
}

// HarnessIdentity says how an agent proves who it is.
//
//   - "pod-token": the agent Pod's own projected token, checked against the
//     live Pod and the connection's source address (Cursor workers).
//   - "session-jwt": the same Pod check, plus a runner session token naming
//     the person, pinned to the first Pod that presents it (Claude sessions).
//   - "proxy-attested": a shared proxy in the agent's cluster runs the Pod
//     check and presents its own token; the broker trusts that one proxy
//     account and the Pod it attests (agent-sandbox).
//
// OwnerKind is the Kubernetes kind of the controller that must own the
// agent's Pod. ImageDigests are the images every container must run.
type HarnessIdentity struct {
	Kind         string            `json:"kind"`
	OwnerKind    string            `json:"ownerKind"`
	Namespaces   []string          `json:"namespaces"`
	ImageDigests []string          `json:"imageDigests"`
	Requester    *HarnessRequester `json:"requester,omitempty"` // optional
}

// HarnessRequester is where the person behind a session comes from:
// "session-jwt" (a runner session token) or "signed-assertion" (a statement
// the launching runtime signs onto the agent's controller object).
type HarnessRequester struct {
	Kind string `json:"kind"`
}

// HarnessPath is how the agent reaches the broker: a "sidecar" in the agent's
// own Pod, or a "shared-proxy" serving many agents. CrossCluster says the
// agents run in another cluster than the broker.
type HarnessPath struct {
	Kind         string `json:"kind"`
	CrossCluster bool   `json:"crossCluster"`
}

// HarnessAuthorization decides access for the "pool" (its ceiling and fixed
// entitlements) or for the "person" behind each session (their groups).
// PoolName is the catalog pool the harness's agents are admitted into.
type HarnessAuthorization struct {
	Mode     string `json:"mode"`
	PoolName string `json:"poolName"`
}

// Identity kinds, path kinds and authorization modes.
const (
	IdentityPodToken      = "pod-token"
	IdentitySessionJWT    = "session-jwt"
	IdentityProxyAttested = "proxy-attested"

	RequesterSessionJWT      = "session-jwt"
	RequesterSignedAssertion = "signed-assertion"

	PathSidecar     = "sidecar"
	PathSharedProxy = "shared-proxy"

	KeysInCluster = "in-cluster"
	KeysRemote    = "remote"

	AuthorizePool   = "pool"
	AuthorizePerson = "person"
)

var (
	kubernetesKind = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	audiencePat    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// validate checks one profile on its own; validateHarnesses checks it against
// the pools.
func (h Harness) validate() error {
	if !idPattern.MatchString(h.Name) {
		return errors.New("name must be a short identifier")
	}
	td := h.TrustDomain
	u, err := url.Parse(td.Issuer)
	if td.Issuer == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(td.Issuer) > 512 {
		return errors.New("trustDomain.issuer must be an HTTPS URL")
	}
	if td.Keys != KeysInCluster && td.Keys != KeysRemote {
		return fmt.Errorf("trustDomain.keys %q: in-cluster or remote", td.Keys)
	}
	if !audiencePat.MatchString(td.Audience) {
		return errors.New("trustDomain.audience is required")
	}
	id := h.Identity
	switch id.Kind {
	case IdentityPodToken, IdentitySessionJWT, IdentityProxyAttested:
	default:
		return fmt.Errorf("identity.kind %q: pod-token, session-jwt or proxy-attested", id.Kind)
	}
	if !kubernetesKind.MatchString(id.OwnerKind) {
		return errors.New("identity.ownerKind must be a Kubernetes kind")
	}
	if len(id.Namespaces) == 0 || len(id.Namespaces) > 16 {
		return errors.New("identity.namespaces needs 1 to 16 namespaces")
	}
	seen := map[string]bool{}
	for _, ns := range id.Namespaces {
		if !dnsLabel.MatchString(ns) || seen[ns] {
			return fmt.Errorf("identity namespace %q is invalid or repeated", ns)
		}
		seen[ns] = true
	}
	if len(id.ImageDigests) == 0 || len(id.ImageDigests) > 16 {
		return errors.New("identity.imageDigests needs 1 to 16 digests")
	}
	for _, d := range id.ImageDigests {
		if !digestPattern.MatchString(d) {
			return errors.New("identity image digest must be sha256: and 64 lowercase hex characters")
		}
	}
	requester := ""
	if id.Requester != nil {
		requester = id.Requester.Kind
		if requester != RequesterSessionJWT && requester != RequesterSignedAssertion {
			return fmt.Errorf("identity.requester.kind %q: session-jwt or signed-assertion", requester)
		}
	}
	switch h.Path.Kind {
	case PathSidecar, PathSharedProxy:
	default:
		return fmt.Errorf("path.kind %q: sidecar or shared-proxy", h.Path.Kind)
	}
	switch h.Authorization.Mode {
	case AuthorizePool, AuthorizePerson:
	default:
		return fmt.Errorf("authorization.mode %q: pool or person", h.Authorization.Mode)
	}
	if !idPattern.MatchString(h.Authorization.PoolName) {
		return errors.New("authorization.poolName is required")
	}
	// The combinations that hold together. Each refusal names the reason.
	switch id.Kind {
	case IdentityPodToken:
		if h.Path.Kind != PathSidecar || requester != "" || h.Authorization.Mode != AuthorizePool {
			return errors.New("pod-token identity runs a sidecar, names no requester and authorizes the pool")
		}
	case IdentitySessionJWT:
		if h.Path.Kind != PathSidecar || (requester != "" && requester != RequesterSessionJWT) || h.Authorization.Mode != AuthorizePerson {
			return errors.New("session-jwt identity runs a sidecar, takes its person from the session and authorizes the person")
		}
	case IdentityProxyAttested:
		if h.Path.Kind != PathSharedProxy || requester == RequesterSessionJWT {
			return errors.New("proxy-attested identity runs a shared proxy and takes no session token")
		}
		if requester == RequesterSignedAssertion {
			// Fail closed until the broker verifies assertions: a profile that
			// names one must not silently run at pool level.
			return errors.New("signed-assertion requesters are not verified by this broker yet")
		}
		if h.Authorization.Mode != AuthorizePool {
			return errors.New("person authorization needs a requester")
		}
	}
	// The broker reads Pods only in its own cluster, so an agent in another
	// cluster is attested by a proxy there, whose keys are fetched remotely.
	if h.Path.CrossCluster != (td.Keys == KeysRemote) {
		return errors.New("a cross-cluster path uses remote keys, and only it does")
	}
	if h.Path.CrossCluster && id.Kind != IdentityProxyAttested {
		return errors.New("a cross-cluster harness must be proxy-attested")
	}
	return nil
}

// validateHarnesses checks every profile and binds it to its pool. When a
// catalog declares harnesses, each pool belongs to exactly one, and the pool's
// identity agrees with the profile's authorization.
func validateHarnesses(harnesses []Harness, pools map[string]Pool) (map[string]Harness, error) {
	if len(harnesses) == 0 {
		return nil, nil
	}
	byPool := map[string]Harness{}
	names := map[string]bool{}
	for _, h := range harnesses {
		if err := h.validate(); err != nil {
			return nil, fmt.Errorf("harness %q: %w", h.Name, err)
		}
		if names[h.Name] {
			return nil, fmt.Errorf("duplicate harness %q", h.Name)
		}
		names[h.Name] = true
		pool, ok := pools[h.Authorization.PoolName]
		if !ok {
			return nil, fmt.Errorf("harness %q names undefined pool %q", h.Name, h.Authorization.PoolName)
		}
		if _, taken := byPool[pool.Name]; taken {
			return nil, fmt.Errorf("pool %q belongs to more than one harness", pool.Name)
		}
		person := pool.Identity == "claude-session"
		if person != (h.Authorization.Mode == AuthorizePerson) {
			return nil, fmt.Errorf("harness %q authorizes the %s, but pool %q has identity %q", h.Name, h.Authorization.Mode, pool.Name, pool.Identity)
		}
		if pool.Namespace != "" && !contains(h.Identity.Namespaces, pool.Namespace) {
			return nil, fmt.Errorf("harness %q does not list pool %q's namespace", h.Name, pool.Name)
		}
		byPool[pool.Name] = h
	}
	for name := range pools {
		if _, ok := byPool[name]; !ok {
			return nil, fmt.Errorf("pool %q has no harness", name)
		}
	}
	return byPool, nil
}

// Profile is the harness a pool's agents are admitted under. Explicit is
// false for a catalog that declares no harnesses: the profile is then derived
// from the pool's identity alone, and names no trust domain, namespaces or
// images to check, which is how the broker behaved before profiles.
type Profile struct {
	Harness
	Explicit bool
}

// Profile returns the pool's profile.
func (p Pool) Profile() Profile {
	if p.harness != nil {
		return Profile{Harness: *p.harness, Explicit: true}
	}
	h := Harness{Name: p.Name, Identity: HarnessIdentity{Kind: IdentityPodToken}, Path: HarnessPath{Kind: PathSidecar},
		Authorization: HarnessAuthorization{Mode: AuthorizePool, PoolName: p.Name}}
	if p.Identity == "claude-session" {
		h.Identity = HarnessIdentity{Kind: IdentitySessionJWT, Requester: &HarnessRequester{Kind: RequesterSessionJWT}}
		h.Authorization.Mode = AuthorizePerson
	}
	return Profile{Harness: h}
}

// RequesterKind is where the person behind a session comes from, or "".
func (p Profile) RequesterKind() string {
	if p.Identity.Requester != nil {
		return p.Identity.Requester.Kind
	}
	if p.Identity.Kind == IdentitySessionJWT {
		return RequesterSessionJWT
	}
	return ""
}

// Harnesses returns the declared profiles.
func (c Catalog) Harnesses() []Harness { return append([]Harness(nil), c.harnesses...) }

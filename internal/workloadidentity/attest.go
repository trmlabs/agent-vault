package workloadidentity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

var _ brokercore.Attestor = (*Resolver)(nil)

const (
	jwksMaxAge         = time.Hour
	jwksRefetchBackoff = 30 * time.Second
	jwksFetchTimeout   = 10 * time.Second
)

// signingKeys caches the cluster's service-account signing keys, so a pool
// worker's token is verified locally instead of by an API call per connection.
// A failed fetch keeps the last good set, and one fetch runs at a time
// outside the lock, so neither an unknown kid nor an API outage stalls or
// fails the admissions the cached keys can still verify.
type signingKeys struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetched   time.Time     // last successful fetch
	attempted time.Time     // last fetch started
	flight    chan struct{} // closed when the running fetch ends
}

func (r *Resolver) signingKey(ctx context.Context, kid string) *rsa.PublicKey {
	j := r.jwks
	for waited := false; ; waited = true {
		j.mu.Lock()
		now := r.now()
		key := j.keys[kid]
		// An unknown kid or an old set triggers a refetch for key rotation, at
		// most every 30 s; meanwhile the last good keys stand.
		if (key != nil && now.Sub(j.fetched) < jwksMaxAge) || waited || (!j.attempted.IsZero() && now.Sub(j.attempted) < jwksRefetchBackoff) {
			j.mu.Unlock()
			return key
		}
		flight := j.flight
		if flight == nil {
			flight = make(chan struct{})
			j.flight, j.attempted = flight, now
			// The fetch serves every waiter, so the caller's cancellation
			// does not end it.
			go r.fetchSigningKeys(context.WithoutCancel(ctx), flight)
		}
		j.mu.Unlock()
		select {
		case <-flight:
		case <-ctx.Done():
			return nil
		}
	}
}

// fetchSigningKeys replaces the key set on success and leaves it alone on
// failure, then releases the waiters.
func (r *Resolver) fetchSigningKeys(ctx context.Context, flight chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	var set struct {
		Keys []struct {
			Kty, Kid, Alg, Use, N, E string
		} `json:"keys"`
	}
	err := r.api(ctx, http.MethodGet, "/openid/v1/jwks", nil, &set)
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exponent := int(new(big.Int).SetBytes(e).Int64())
		if exponent < 3 || exponent%2 == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	j := r.jwks
	j.mu.Lock()
	if err == nil {
		j.keys, j.fetched = keys, r.now()
	}
	j.flight = nil
	j.mu.Unlock()
	close(flight)
}

// verifyLocally checks the token's signature against the cluster keys and its
// claims against policy. It is authentication, not a pre-filter.
func (r *Resolver) verifyLocally(ctx context.Context, token string, renewal bool) (claims, error) {
	deny := brokercore.ErrInvalidSession
	if len(token) == 0 || len(token) > 32768 {
		return claims{}, deny
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return claims{}, deny
	}
	headerBytes, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return claims{}, deny
	}
	var header struct {
		Alg, Kid, Typ string
		Crit          []string
	}
	var c claims
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Kid == "" || len(header.Crit) != 0 || json.Unmarshal(payload, &c) != nil {
		return claims{}, deny
	}
	now := r.now().Unix()
	// A renewal recheck of an open session accepts an expired token; its Pod
	// must still qualify below. A new connection needs an unexpired token.
	if c.Issuer != r.config.Issuer || !exactly(c.Audience, r.config.Audience) || (c.Expires <= now && !renewal) || c.Issued <= 0 || c.Issued > now+60 || c.NotBefore > now+60 || c.Expires <= c.Issued || c.Expires-c.Issued > r.config.MaxTokenLifetimeSeconds {
		return claims{}, deny
	}
	k := c.Kubernetes
	if k.Pod.UID == "" || !pathSegment(k.Pod.Name) || !pathSegment(k.Namespace) || k.ServiceAccount.UID == "" || c.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
		return claims{}, deny
	}
	key := r.signingKey(ctx, header.Kid)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if key == nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return claims{}, deny
	}
	return c, nil
}

type livePod struct {
	Metadata struct {
		UID               string  `json:"uid"`
		Name              string  `json:"name"`
		Namespace         string  `json:"namespace"`
		DeletionTimestamp *string `json:"deletionTimestamp"`
		OwnerReferences   []struct {
			UID                string `json:"uid"`
			Controller         *bool  `json:"controller"`
			BlockOwnerDeletion *bool  `json:"blockOwnerDeletion"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName    string `json:"serviceAccountName"`
		ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds"`
	} `json:"spec"`
	Status struct {
		Phase             string                `json:"phase"`
		PodIP             string                `json:"podIP"`
		PodIPs            []struct{ IP string } `json:"podIPs"`
		StartTime         *time.Time            `json:"startTime"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			RestartCount int    `json:"restartCount"`
			State        struct {
				Running *struct{} `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// deadline returns when the Pod's admission ends, or the zero time if it is
// not an admissible pool Pod right now.
func (p *livePod) deadline(b *Binding, c claims, peer netip.Addr, now time.Time) time.Time {
	k := c.Kubernetes
	m := p.Metadata
	if m.UID != k.Pod.UID || m.Name != k.Pod.Name || m.Namespace != k.Namespace || m.DeletionTimestamp != nil ||
		p.Spec.ServiceAccountName != k.ServiceAccount.Name || p.Status.Phase != "Running" || p.Status.StartTime == nil {
		return time.Time{}
	}
	// Second check: the connection came from this Pod's own address.
	addresses := []string{p.Status.PodIP}
	for _, ip := range p.Status.PodIPs {
		addresses = append(addresses, ip.IP)
	}
	matched := false
	for _, a := range addresses {
		if parsed, err := netip.ParseAddr(a); err == nil && parsed == peer {
			matched = true
		}
	}
	if !matched {
		return time.Time{}
	}
	// ownerReferences are written by whoever creates the Pod, so this is not
	// proof the controller made it: anyone who may create Pods under this
	// service account in this namespace can name an approved controller.
	// That right, restricted by RBAC or an admission policy, is the boundary.
	// Controllers always set blockOwnerDeletion, and with the
	// OwnerReferencesPermissionEnforcement admission plugin setting it needs
	// update rights on the owner's finalizers, so it is required.
	owned := false
	for _, owner := range m.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion {
			for _, approved := range b.OwnerUIDs {
				owned = owned || owner.UID == approved
			}
		}
	}
	if !owned {
		return time.Time{}
	}
	if b.ContainerName != "" {
		running := 0
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == b.ContainerName {
				if s.State.Running == nil || s.RestartCount != 0 {
					return time.Time{}
				}
				running++
			}
		}
		if running != 1 {
			return time.Time{}
		}
	}
	end := p.Status.StartTime.Add(time.Duration(b.MaxPodSeconds) * time.Second)
	if d := p.Spec.ActiveDeadlineSeconds; d != nil {
		if active := p.Status.StartTime.Add(time.Duration(*d) * time.Second); active.Before(end) {
			end = active
		}
	}
	if !now.Before(end) {
		return time.Time{}
	}
	return end
}

// Attest admits a pool worker: local token verification first, then the live
// Pod must be the connection's peer, Running, owned by an approved controller
// and inside its deadline. Bindings without approved owners keep the online
// TokenReview path of ResolveForProxy.
func (r *Resolver) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	return r.attest(ctx, token, peer, false)
}

// Reattest is the periodic recheck of an open session: the same checks, except
// that the connection's original token may have expired since admission.
func (r *Resolver) Reattest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	return r.attest(ctx, token, peer, true)
}

func (r *Resolver) attest(ctx context.Context, token string, peer netip.Addr, renewal bool) (*brokercore.ProxyScope, error) {
	deny := brokercore.ErrInvalidSession
	if !peer.IsValid() || peer.IsLoopback() || peer.IsUnspecified() {
		return nil, deny
	}
	peer = peer.Unmap()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	c, err := r.verifyLocally(ctx, token, renewal)
	if err != nil {
		return nil, err
	}
	k := c.Kubernetes
	var binding *Binding
	for i := range r.config.Bindings {
		b := &r.config.Bindings[i]
		if b.Namespace == k.Namespace && b.ServiceAccount == k.ServiceAccount.Name && b.ServiceAccountUID == k.ServiceAccount.UID {
			binding = b
			break
		}
	}
	if binding == nil {
		return nil, deny
	}
	if len(binding.OwnerUIDs) == 0 {
		return r.ResolveForProxy(ctx, token, "")
	}
	var pod livePod
	if r.api(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(k.Namespace)+"/pods/"+url.PathEscape(k.Pod.Name), nil, &pod) != nil {
		return nil, deny
	}
	notAfter := pod.deadline(binding, c, peer, r.now())
	if notAfter.IsZero() {
		return nil, deny
	}
	scope, err := r.grant(ctx, binding, "")
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (c.Expires <= r.now().Unix() && !renewal) || !r.now().Before(notAfter) {
		return nil, deny
	}
	scope.WorkloadID, scope.NotAfter, scope.Pool = k.Pod.UID, notAfter, binding.Pool
	return scope, nil
}

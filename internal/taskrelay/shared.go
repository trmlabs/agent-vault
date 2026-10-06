package taskrelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/imagerule"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// SharedConfig runs the relay as one shared proxy for many agent Pods, for a
// runtime whose Pods can hold no token of their own (agent-sandbox). The
// proxy matches each connection's source address to one live agent Pod in
// its own cluster, checks that Pod, and presents its own projected token to
// the broker with an attestation of the Pod. The broker trusts this proxy's
// service account alone, and only from the private link it is reached over.
type SharedConfig struct {
	// Profiles maps each namespace the agent Pods run in to its harness
	// profile, which the attestation names; the broker refuses a profile its
	// own map does not give that namespace. The proxy lists and watches Pods
	// in each namespace, so its Role needs get, list and watch on pods there.
	Profiles map[string]string `json:"profiles"`
	// OwnerKind and OwnerAPIVersion name the controller that must own each
	// agent Pod, such as Sandbox and agents.x-k8s.io/v1beta1.
	OwnerKind       string `json:"ownerKind"`
	OwnerAPIVersion string `json:"ownerAPIVersion"`
	// ImagePrefixes maps a namespace to the agent-sandbox repository path its
	// agents' images are pulled from (see imagerule.ValidPrefix). ImageDigests
	// are exact digests allowed in every namespace, for containers the
	// platform injects. Each container must match one or the other, judged on
	// the image the node pulled, never the Pod spec.
	ImagePrefixes map[string]string `json:"imagePrefixes,omitempty"`
	ImageDigests  []string          `json:"imageDigests,omitempty"`
	// MaxPodSeconds bounds an agent Pod's admission from its start (60 s to 8 h).
	MaxPodSeconds int64 `json:"maxPodSeconds"`
	// MaxConnections bounds the open connections of one replica (default
	// 4096). Scale out with replicas, not by raising it.
	MaxConnections int `json:"maxConnections,omitempty"`
}

const (
	defaultSharedConnections = 4096
	// watchSeconds is how long one watch request runs before it is renewed;
	// outOfSync how long a namespace's watch may be down before its Pods stop
	// being admitted; watchIdle how long a silent stream is trusted before it
	// is treated as dead.
	watchSeconds = 60
	outOfSync    = 10 * time.Second
	watchIdle    = 75 * time.Second
)

var (
	kindPattern       = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	apiVersionPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?v[0-9]+((alpha|beta)[0-9]+)?$`)
	dnsLabel          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	profileName       = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$`)
)

// namespaces are the watched namespaces, in a fixed order.
func (s *SharedConfig) namespaces() []string {
	out := make([]string, 0, len(s.Profiles))
	for ns := range s.Profiles {
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

func (s *SharedConfig) validate() error {
	if len(s.Profiles) == 0 || len(s.Profiles) > 64 || !kindPattern.MatchString(s.OwnerKind) || !apiVersionPattern.MatchString(s.OwnerAPIVersion) ||
		len(s.ImageDigests) > 16 || s.MaxPodSeconds < 60 || s.MaxPodSeconds > 8*3600 || s.MaxConnections < 0 || s.MaxConnections > 65536 {
		return errConfig
	}
	for ns, profile := range s.Profiles {
		if !dnsLabel.MatchString(ns) || !profileName.MatchString(profile) {
			return errConfig
		}
		// A namespace with no prefix runs listed digests only.
		if s.ImagePrefixes[ns] == "" && len(s.ImageDigests) == 0 {
			return errConfig
		}
	}
	for ns, prefix := range s.ImagePrefixes {
		if s.Profiles[ns] == "" || !imagerule.ValidPrefix(prefix) {
			return errConfig
		}
		for other, otherPrefix := range s.ImagePrefixes {
			if other != ns && imagerule.Overlap(prefix, otherPrefix) {
				return errConfig
			}
		}
	}
	for _, d := range s.ImageDigests {
		if !imagerule.ValidDigest(d) {
			return errConfig
		}
	}
	return nil
}

func (s *SharedConfig) connections() int {
	if s.MaxConnections == 0 {
		return defaultSharedConnections
	}
	return s.MaxConnections
}

// validateShared allows TLS listeners on any address, Kubernetes access for
// the Pod cache, no pairing, no browser and no session files.
func (c FixedConfig) validateShared(now time.Time) error {
	if c.Self || c.Browser != nil || c.Sandbox != (SandboxConfig{}) || c.Shared.validate() != nil {
		return errConfig
	}
	// Plaintext listeners are allowed (no certificate and no key) on the Pod
	// network; the HTTP listener takes CONNECT only, so HTTPS stays end to
	// end, and every upstream to the broker is TLS.
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.AuditFile == "" || (c.TLSCertFile == "") != (c.TLSKeyFile == "") ||
		c.Kubernetes.CAFile == "" || c.Kubernetes.ReviewerTokenFile == "" {
		return errConfig
	}
	u, e := url.Parse(c.Kubernetes.APIURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errConfig
	}
	used := map[string]bool{}
	check := func(listen string, upstream UpstreamConfig) error {
		if !validAddress(listen) || used[listen] || upstream.SessionFile != "" || !validAddress(upstream.Address) || upstream.ServerName == "" || upstream.CAFile == "" || upstream.ProofFile == "" || upstream.Audience == "" {
			return errConfig
		}
		used[listen] = true
		return nil
	}
	if c.Connect != nil {
		if check(c.Connect.Listen, c.Connect.Upstream) != nil || len(c.Connect.AllowedTargets) == 0 || len(c.Connect.AllowedTargets) > 32 {
			return errConfig
		}
		for _, target := range c.Connect.AllowedTargets {
			if !validAddress(target) {
				return errConfig
			}
		}
	}
	if len(c.PostgresBindings) > 8 || (c.Postgres != nil && len(c.PostgresBindings) != 0) {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if check(p.Listen, p.Upstream) != nil || !safeName.MatchString(p.Database) || !safeName.MatchString(p.User) || !safeName.MatchString(p.Placeholder) {
			return errConfig
		}
	}
	// A broker-issued certificate replaces the files, and is requested over
	// the CONNECT listener's upstream: the broker's cross-cluster listener.
	if c.TLS != nil && (c.TLS.validate() != nil || c.TLSCertFile != "" || c.Connect == nil) {
		return errConfig
	}
	if l := c.PostgresListener; l != nil {
		if check(l.Listen, l.Upstream) != nil || len(l.Databases) == 0 || !safeName.MatchString(l.User) || !safeName.MatchString(l.Placeholder) {
			return errConfig
		}
		seen := make(map[string]bool, len(l.Databases))
		for _, name := range l.Databases {
			if !safeName.MatchString(name) || seen[name] {
				return errConfig
			}
			seen[name] = true
		}
	}
	if len(used) == 0 {
		return errConfig
	}
	if c.AdminListen != "" && (!validAddress(c.AdminListen) || used[c.AdminListen]) {
		return errConfig
	}
	return nil
}

// agentPod is the part of a Pod the shared proxy checks.
type agentPod struct {
	Metadata struct {
		Name              string  `json:"name"`
		Namespace         string  `json:"namespace"`
		UID               string  `json:"uid"`
		DeletionTimestamp *string `json:"deletionTimestamp"`
		OwnerReferences   []struct {
			APIVersion         string `json:"apiVersion"`
			Kind               string `json:"kind"`
			UID                string `json:"uid"`
			Controller         *bool  `json:"controller"`
			BlockOwnerDeletion *bool  `json:"blockOwnerDeletion"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		HostNetwork           bool       `json:"hostNetwork"`
		ActiveDeadlineSeconds *int64     `json:"activeDeadlineSeconds"`
		EphemeralContainers   []struct{} `json:"ephemeralContainers"`
	} `json:"spec"`
	Status struct {
		Phase                 string                     `json:"phase"`
		PodIP                 string                     `json:"podIP"`
		PodIPs                []struct{ IP string }      `json:"podIPs"`
		StartTime             *time.Time                 `json:"startTime"`
		ContainerStatuses     []struct{ ImageID string } `json:"containerStatuses"`
		InitContainerStatuses []struct{ ImageID string } `json:"initContainerStatuses"`
	} `json:"status"`
}

func (p *agentPod) addresses() []netip.Addr {
	var out []netip.Addr
	for _, s := range append([]string{p.Status.PodIP}, func() []string {
		var ips []string
		for _, ip := range p.Status.PodIPs {
			ips = append(ips, ip.IP)
		}
		return ips
	}()...) {
		if a, err := netip.ParseAddr(s); err == nil && !slices.Contains(out, a.Unmap()) {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// attest returns the Pod's attestation if it is an admissible agent right now.
func (p *agentPod) attest(s *SharedConfig, now time.Time) (workloadidentity.Attestation, bool) {
	var a workloadidentity.Attestation
	m := p.Metadata
	if m.DeletionTimestamp != nil || m.UID == "" || p.Spec.HostNetwork || p.Status.Phase != "Running" || p.Status.StartTime == nil ||
		len(p.Spec.EphemeralContainers) != 0 || len(p.Status.ContainerStatuses) == 0 || s.Profiles[m.Namespace] == "" {
		return a, false
	}
	// The controller reference names the agent's own controller object. Only
	// the controller may create Pods in an agent namespace; that right is the
	// boundary, as for pool Pods.
	owner := ""
	for _, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			if owner != "" || o.Kind != s.OwnerKind || o.APIVersion != s.OwnerAPIVersion || o.UID == "" || o.BlockOwnerDeletion == nil || !*o.BlockOwnerDeletion {
				return a, false
			}
			owner = o.UID
		}
	}
	if owner == "" {
		return a, false
	}
	var images []string
	for _, c := range append(append([]struct{ ImageID string }(nil), p.Status.ContainerStatuses...), p.Status.InitContainerStatuses...) {
		if !imagerule.Allowed(c.ImageID, s.ImagePrefixes[m.Namespace], s.ImageDigests) {
			return a, false
		}
		if image := strings.TrimPrefix(c.ImageID, "docker-pullable://"); !slices.Contains(images, image) {
			images = append(images, image)
		}
	}
	end := p.Status.StartTime.Add(time.Duration(s.MaxPodSeconds) * time.Second)
	if d := p.Spec.ActiveDeadlineSeconds; d != nil {
		if active := p.Status.StartTime.Add(time.Duration(*d) * time.Second); active.Before(end) {
			end = active
		}
	}
	if !now.Before(end) {
		return a, false
	}
	return workloadidentity.Attestation{Namespace: m.Namespace, PodName: m.Name, PodUID: m.UID, OwnerKind: s.OwnerKind, OwnerUID: owner,
		Images: images, NotAfter: end.Unix(), Profile: s.Profiles[m.Namespace]}, true
}

// podCache holds the agent Pods of every watched namespace, kept current by
// one list and watch per namespace: no API call per connection. A namespace
// whose watch has been down for more than outOfSync admits nothing.
type podCache struct {
	config *SharedConfig
	k8s    KubernetesConfig
	client *http.Client
	now    func() time.Time
	mu     sync.RWMutex
	pods   map[string]*agentPod               // namespace/name
	byIP   map[netip.Addr]map[string]struct{} // address to namespace/name
	inSync map[string]bool                    // namespace to whether its watch is open
	lostAt map[string]time.Time               // namespace to when its watch last went down
	// activity is each agent Pod's last use of this replica; a Pod that
	// leaves the cache is forgotten.
	activity *activity
}

func newPodCache(c FixedConfig) (*podCache, error) {
	t, e := clientTLS(c.Kubernetes.CAFile, "")
	if e != nil {
		return nil, e
	}
	// No overall timeout: a watch is a long response. Each request carries a
	// context deadline instead.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: t, Proxy: nil, MaxResponseHeaderBytes: 8192},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied }}
	return &podCache{config: c.Shared, k8s: c.Kubernetes, client: client, now: time.Now,
		pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, inSync: map[string]bool{}, lostAt: map[string]time.Time{},
		activity: newActivity(time.Now())}, nil
}

// lookup returns the attestation of the one admissible agent Pod at peer.
func (c *podCache) lookup(peer netip.Addr) (workloadidentity.Attestation, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	var found workloadidentity.Attestation
	matches := 0
	for key := range c.byIP[peer.Unmap()] {
		p := c.pods[key]
		if p == nil || !c.synced(p.Metadata.Namespace, now) {
			continue
		}
		if a, ok := p.attest(c.config, now); ok {
			found = a
			matches++
		}
	}
	// Two live Pods claiming one address is never resolved by guessing.
	return found, matches == 1
}

func (c *podCache) put(key string, p *agentPod) {
	c.remove(key)
	c.pods[key] = p
	for _, a := range p.addresses() {
		if c.byIP[a] == nil {
			c.byIP[a] = map[string]struct{}{}
		}
		c.byIP[a][key] = struct{}{}
	}
}

func (c *podCache) remove(key string) {
	old := c.pods[key]
	if old == nil {
		return
	}
	for _, a := range old.addresses() {
		delete(c.byIP[a], key)
		if len(c.byIP[a]) == 0 {
			delete(c.byIP, a)
		}
	}
	delete(c.pods, key)
	c.activity.forget(old.Metadata.UID)
}

// replace swaps one namespace's Pods for a fresh list.
func (c *podCache) replace(namespace string, pods []*agentPod) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, p := range c.pods {
		if p.Metadata.Namespace == namespace {
			c.remove(key)
		}
	}
	for _, p := range pods {
		if p.Metadata.Namespace == namespace {
			c.put(namespace+"/"+p.Metadata.Name, p)
		}
	}
	c.inSync[namespace] = true
}

// synced reports whether a namespace's Pods are current enough to admit:
// its watch is open, or went down no more than outOfSync ago. A namespace
// never listed is not.
func (c *podCache) synced(namespace string, now time.Time) bool {
	if c.inSync[namespace] {
		return true
	}
	lost, ok := c.lostAt[namespace]
	return ok && now.Sub(lost) <= outOfSync
}

// heard marks a namespace's watch open.
func (c *podCache) heard(namespace string) {
	c.mu.Lock()
	c.inSync[namespace] = true
	c.mu.Unlock()
}

// lost marks a namespace's watch down from now.
func (c *podCache) lost(namespace string) {
	c.mu.Lock()
	if c.inSync[namespace] {
		c.inSync[namespace], c.lostAt[namespace] = false, c.now()
	}
	c.mu.Unlock()
}

// run keeps every namespace current until ctx ends.
func (c *podCache) run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, ns := range c.config.namespaces() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if c.sync(ctx, ns) != nil {
					select {
					case <-ctx.Done():
					case <-time.After(time.Second):
					}
				}
			}
		}()
	}
	wg.Wait()
}

// waitSynced reports whether every namespace has been listed once.
func (c *podCache) waitSynced(ctx context.Context) error {
	for {
		c.mu.RLock()
		ready := true
		for _, ns := range c.config.namespaces() {
			ready = ready && c.inSync[ns]
		}
		c.mu.RUnlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return errDenied
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// sync lists one namespace, then watches it from that version until the
// watch ends or fails; the caller lists again.
func (c *podCache) sync(ctx context.Context, ns string) error {
	defer c.lost(ns)
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
			Continue        string `json:"continue"`
		} `json:"metadata"`
		Items []*agentPod `json:"items"`
	}
	var pods []*agentPod
	next := ""
	for {
		query := url.Values{"limit": {"500"}}
		if next != "" {
			query.Set("continue", next)
		}
		list.Items, list.Metadata.Continue = nil, ""
		if e := c.get(ctx, ns, query, 30*time.Second, func(body io.Reader) error {
			return json.NewDecoder(io.LimitReader(body, 64<<20)).Decode(&list)
		}); e != nil {
			return e
		}
		pods = append(pods, list.Items...)
		if next = list.Metadata.Continue; next == "" {
			break
		}
	}
	c.replace(ns, pods)
	version := list.Metadata.ResourceVersion
	for ctx.Err() == nil {
		query := url.Values{"watch": {"1"}, "resourceVersion": {version}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"60"}}
		gone := false
		e := c.get(ctx, ns, query, (watchSeconds+15)*time.Second, func(body io.Reader) error {
			c.heard(ns)
			decoder := json.NewDecoder(body)
			for {
				var event struct {
					Type   string          `json:"type"`
					Object json.RawMessage `json:"object"`
				}
				if e := decoder.Decode(&event); e != nil {
					if errors.Is(e, io.EOF) {
						return nil
					}
					return e
				}
				var p agentPod
				var meta struct {
					Metadata struct {
						ResourceVersion string `json:"resourceVersion"`
					} `json:"metadata"`
				}
				if json.Unmarshal(event.Object, &p) != nil || json.Unmarshal(event.Object, &meta) != nil {
					return errDenied
				}
				c.mu.Lock()
				switch event.Type {
				case "ADDED", "MODIFIED":
					if p.Metadata.Namespace == ns {
						c.put(ns+"/"+p.Metadata.Name, &p)
					}
				case "DELETED":
					c.remove(ns + "/" + p.Metadata.Name)
				case "BOOKMARK":
				default: // ERROR, such as 410 Gone: list again.
					gone = true
				}
				c.mu.Unlock()
				if gone {
					return errDenied
				}
				if meta.Metadata.ResourceVersion != "" {
					version = meta.Metadata.ResourceVersion
				}
			}
		})
		// The watch ended; until the next one opens, the namespace counts as down.
		c.lost(ns)
		if e != nil {
			return e
		}
	}
	return ctx.Err()
}

// get makes one API request for a namespace's Pods. A response that goes
// quiet for watchIdle is abandoned, so a silently dead watch cannot keep
// stale Pods admitted.
func (c *podCache) get(ctx context.Context, ns string, query url.Values, limit time.Duration, read func(io.Reader) error) error {
	token, e := readBoundedFile(c.k8s.ReviewerTokenFile, 32<<10)
	if e != nil || strings.TrimSpace(string(token)) == "" {
		return errDenied
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	endpoint := strings.TrimRight(c.k8s.APIURL, "/") + "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods?" + query.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return errDenied
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, e := c.client.Do(req)
	if e != nil {
		return errDenied
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errDenied
	}
	idle := time.AfterFunc(watchIdle, cancel)
	defer idle.Stop()
	return read(&idleReader{r: resp.Body, timer: idle})
}

// idleReader pushes back the idle timer on every read that returns data.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
}

func (r *idleReader) Read(b []byte) (int, error) {
	n, e := r.r.Read(b)
	if n > 0 {
		r.timer.Reset(watchIdle)
	}
	return n, e
}

// sharedPeer resolves a connection's source to its agent Pod.
func sharedPeer(peer string) (netip.Addr, bool) {
	host, _, e := net.SplitHostPort(peer)
	if e != nil {
		return netip.Addr{}, false
	}
	a, e := netip.ParseAddr(host)
	// Only an address the API server reports for an agent Pod can match.
	if e != nil || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

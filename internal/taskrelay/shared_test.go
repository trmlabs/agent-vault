package taskrelay

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

const (
	sandboxDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	otherDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// sandboxPod is an agent-sandbox Pod: owned by its Sandbox, running one
// approved image, at ip.
func sandboxPod(name, uid, ip string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "agent-sandboxes", "uid": uid, "resourceVersion": "5",
			"ownerReferences": []any{map[string]any{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox", "uid": "sandbox-" + uid, "controller": true, "blockOwnerDeletion": true}}},
		"spec": map[string]any{},
		"status": map[string]any{"phase": "Running", "podIP": ip, "startTime": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
			"containerStatuses": []any{map[string]any{"imageID": "registry.example/agent@" + sandboxDigest}}},
	}
}

func sharedConfig() *SharedConfig {
	return &SharedConfig{Namespaces: []string{"agent-sandboxes"}, OwnerKind: "Sandbox", OwnerAPIVersion: "agents.x-k8s.io/v1beta1",
		ImageDigests: []string{sandboxDigest}, MaxPodSeconds: 3600}
}

// fakeAPI serves a namespace's Pods: one list, then a watch that streams the
// events the test sends.
type fakeAPI struct {
	srv    *httptest.Server
	mu     sync.Mutex
	pods   []map[string]any
	events chan string
	lists  int
}

func newFakeAPI(t *testing.T, f *relayFixture, pods ...map[string]any) *fakeAPI {
	t.Helper()
	api := &fakeAPI{pods: pods, events: make(chan string, 16)}
	api.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/agent-sandboxes/pods" || r.Header.Get("Authorization") != "Bearer synthetic-reviewer" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Query().Get("watch") != "1" {
			api.mu.Lock()
			api.lists++
			items := append([]map[string]any(nil), api.pods...)
			api.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "10"}, "items": items})
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case e := <-api.events:
				io.WriteString(w, e+"\n")
				w.(http.Flusher).Flush()
			case <-time.After(5 * time.Second):
				return
			}
		}
	}))
	api.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	api.srv.StartTLS()
	t.Cleanup(api.srv.Close)
	return api
}

func (api *fakeAPI) send(t *testing.T, kind string, pod map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"type": kind, "object": pod})
	api.events <- string(b)
}

// The shared proxy attests the agent Pod at the connection's source, and
// drops the tunnel once that Pod stops qualifying.
func TestSharedProxyAttestsThenDropsTheAgent(t *testing.T) {
	f := newRelayFixture(t)
	api := newFakeAPI(t, f, sandboxPod("sandbox-a", "pod-a", "127.0.0.1"))
	attested := make(chan string, 4)
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attested <- r.Header.Get("Gatehouse-Attestation")
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	}))
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	broker.StartTLS()
	defer broker.Close()
	f.c.Sandbox = SandboxConfig{}
	f.c.Kubernetes.APIURL = api.srv.URL
	f.c.Shared = sharedConfig()
	f.c.Deadline = time.Now().Add(time.Hour)
	f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
	f.start(t)

	c := f.dial(t, f.c.Connect.Listen)
	io.WriteString(c, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n\r\n")
	b := bufio.NewReader(c)
	response, e := http.ReadResponse(b, &http.Request{Method: "CONNECT"})
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("connect: %v %v", e, response)
	}
	defer response.Body.Close()
	raw, _ := base64.RawURLEncoding.DecodeString(<-attested)
	var a workloadidentity.Attestation
	if json.Unmarshal(raw, &a) != nil || a.PodUID != "pod-a" || a.OwnerUID != "sandbox-pod-a" || a.OwnerKind != "Sandbox" || a.Namespace != "agent-sandboxes" || a.NotAfter <= time.Now().Unix() {
		t.Fatalf("attestation %s", raw)
	}
	io.WriteString(c, "hello")
	echo := make([]byte, 5)
	if _, e := io.ReadFull(b, echo); e != nil || string(echo) != "hello" {
		t.Fatal("tunnel did not relay")
	}
	// The Sandbox is deleted: its Pod starts terminating.
	gone := sandboxPod("sandbox-a", "pod-a", "127.0.0.1")
	gone["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	api.send(t, "MODIFIED", gone)
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, e := b.ReadByte(); e == nil {
		t.Fatal("a deleted agent's tunnel stayed open")
	}
	// A new connection from the same address is refused.
	c2 := f.dial(t, f.c.Connect.Listen)
	io.WriteString(c2, "CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n\r\n")
	r2, e := http.ReadResponse(bufio.NewReader(c2), &http.Request{Method: "CONNECT"})
	if e == nil {
		defer r2.Body.Close()
		if r2.StatusCode == 200 {
			t.Fatal("a deleted agent was admitted")
		}
	}
}

// Every Pod that is not exactly one admissible agent is refused.
func TestSharedLookupRefusals(t *testing.T) {
	ip := netip.MustParseAddr("10.8.0.4")
	cases := map[string]func(p map[string]any) []map[string]any{
		"owned by a ReplicaSet": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["kind"] = "ReplicaSet"
			return []map[string]any{p}
		},
		"owner from another API group": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["apiVersion"] = "example.com/v1"
			return []map[string]any{p}
		},
		"owner is not the controller": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["controller"] = false
			return []map[string]any{p}
		},
		"no blockOwnerDeletion": func(p map[string]any) []map[string]any {
			delete(p["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any), "blockOwnerDeletion")
			return []map[string]any{p}
		},
		"unapproved image": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["containerStatuses"] = []any{map[string]any{"imageID": "r@" + sandboxDigest}, map[string]any{"imageID": "r@" + otherDigest}}
			return []map[string]any{p}
		},
		"ephemeral container added": func(p map[string]any) []map[string]any {
			p["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debug"}}
			return []map[string]any{p}
		},
		"host network": func(p map[string]any) []map[string]any {
			p["spec"].(map[string]any)["hostNetwork"] = true
			return []map[string]any{p}
		},
		"not running": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["phase"] = "Pending"
			return []map[string]any{p}
		},
		"past its deadline": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["startTime"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
			return []map[string]any{p}
		},
		"another namespace": func(p map[string]any) []map[string]any {
			p["metadata"].(map[string]any)["namespace"] = "kube-system"
			return []map[string]any{p}
		},
		"two live Pods on one address": func(p map[string]any) []map[string]any {
			return []map[string]any{p, sandboxPod("sandbox-b", "pod-b", ip.String())}
		},
		"no Pod at the address": func(p map[string]any) []map[string]any {
			p["status"].(map[string]any)["podIP"] = "10.8.0.5"
			return []map[string]any{p}
		},
	}
	for name, build := range cases {
		cache := &podCache{config: sharedConfig(), now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, contact: map[string]time.Time{}}
		cache.replace("agent-sandboxes", decodePods(t, build(sandboxPod("sandbox-a", "pod-a", ip.String()))))
		if a, ok := cache.lookup(ip); ok {
			t.Errorf("%s: admitted %+v", name, a)
		}
	}
	// The positive control, and a stale watch.
	cache := &podCache{config: sharedConfig(), now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{}, contact: map[string]time.Time{}}
	cache.replace("agent-sandboxes", decodePods(t, []map[string]any{sandboxPod("sandbox-a", "pod-a", ip.String())}))
	if _, ok := cache.lookup(ip); !ok {
		t.Fatal("admissible agent refused")
	}
	cache.now = func() time.Time { return time.Now().Add(staleAfter + time.Second) }
	if _, ok := cache.lookup(ip); ok {
		t.Fatal("admitted from a stale watch")
	}
}

func decodePods(t *testing.T, pods []map[string]any) []*agentPod {
	t.Helper()
	var out []*agentPod
	for _, p := range pods {
		b, _ := json.Marshal(p)
		var pod agentPod
		if e := json.Unmarshal(b, &pod); e != nil {
			t.Fatal(e)
		}
		out = append(out, &pod)
	}
	return out
}

func TestSharedConfigValidation(t *testing.T) {
	f := newRelayFixture(t)
	base := func() FixedConfig {
		c := f.c
		c.Sandbox, c.Shared = SandboxConfig{}, sharedConfig()
		c.Connect = &ConnectConfig{Listen: "0.0.0.0:8443", Upstream: f.upstream(t, "broker.internal:443"), AllowedTargets: []string{"api.example.com:443"}}
		return c
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("valid shared config refused: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"also self": func(c *FixedConfig) { c.Self = true },
		"also paired": func(c *FixedConfig) {
			c.Sandbox = SandboxConfig{Namespace: "n", Name: "x", UID: "u", PodIP: "10.0.0.1", ContainerName: "c"}
		},
		"browser":              func(c *FixedConfig) { c.Browser = &BrowserConfig{Listen: "0.0.0.0:9443", Upstream: c.Connect.Upstream} },
		"session file":         func(c *FixedConfig) { c.Connect.Upstream.SessionFile = "/var/run/session" },
		"no TLS":               func(c *FixedConfig) { c.TLSCertFile = "" },
		"no Kubernetes access": func(c *FixedConfig) { c.Kubernetes.ReviewerTokenFile = "" },
		"no namespaces":        func(c *FixedConfig) { c.Shared.Namespaces = nil },
		"no owner kind":        func(c *FixedConfig) { c.Shared.OwnerKind = "" },
		"bad API version":      func(c *FixedConfig) { c.Shared.OwnerAPIVersion = "agents" },
		"no image digests":     func(c *FixedConfig) { c.Shared.ImageDigests = nil },
		"image tag":            func(c *FixedConfig) { c.Shared.ImageDigests = []string{"agent:latest"} },
		"no Pod lifetime":      func(c *FixedConfig) { c.Shared.MaxPodSeconds = 0 },
		"too many connections": func(c *FixedConfig) { c.Shared.MaxConnections = 1 << 20 },
		"no listener":          func(c *FixedConfig) { c.Connect = nil },
	} {
		c := base()
		shared := *c.Shared
		c.Shared = &shared
		connect := *c.Connect
		c.Connect = &connect
		mutate(&c)
		if e := c.Validate(time.Now()); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

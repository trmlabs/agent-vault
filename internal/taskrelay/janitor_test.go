package taskrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeJanitorAPI serves the proxy's replica Pods and a tenant's Sandboxes in
// pages, and records deletes.
type fakeJanitorAPI struct {
	srv       *httptest.Server
	mu        sync.Mutex
	sandboxes []map[string]any
	replicas  []map[string]any
	deleted   map[string]bool
	inFlight  atomic.Int32
	maxFlight atomic.Int32
	// throttle answers this many deletes with 429 first; failName answers 500.
	throttle atomic.Int32
	failName string
	lists    atomic.Int32
	// scaled and progressed are the proxy autoscaler's lastScaleTime and the
	// Deployment's Progressing lastUpdateTime; scaleStatus answers both reads.
	scaled, progressed time.Time
	scaleStatus        int
}

const tenantNS = "developers-sandboxes"

func newFakeJanitorAPI(t *testing.T, f *relayFixture) *fakeJanitorAPI {
	t.Helper()
	api := &fakeJanitorAPI{deleted: map[string]bool{}, scaled: time.Now().Add(-3 * time.Hour), progressed: time.Now().Add(-3 * time.Hour)}
	api.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-reviewer" {
			w.WriteHeader(403)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/gatehouse-proxy/pods":
			if r.URL.Query().Get("labelSelector") != "app=gatehouse-proxy" {
				w.WriteHeader(400)
				return
			}
			api.mu.Lock()
			items := append([]map[string]any(nil), api.replicas...)
			api.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": items})
		case r.Method == "GET" && r.URL.Path == "/apis/autoscaling/v2/namespaces/gatehouse-proxy/horizontalpodautoscalers/gatehouse-proxy":
			if api.scaleStatus != 0 {
				w.WriteHeader(api.scaleStatus)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"lastScaleTime": api.scaled.UTC().Format(time.RFC3339)}})
		case r.Method == "GET" && r.URL.Path == "/apis/apps/v1/namespaces/gatehouse-proxy/deployments/gatehouse-proxy":
			if api.scaleStatus != 0 {
				w.WriteHeader(api.scaleStatus)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"conditions": []any{
				map[string]any{"type": "Available", "lastUpdateTime": time.Now().UTC().Format(time.RFC3339)},
				map[string]any{"type": "Progressing", "lastUpdateTime": api.progressed.UTC().Format(time.RFC3339)}}}})
		case r.Method == "GET" && r.URL.Path == "/apis/agents.x-k8s.io/v1beta1/namespaces/"+tenantNS+"/sandboxes":
			api.lists.Add(1)
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
			api.mu.Lock()
			end := min(start+limit, len(api.sandboxes))
			items := append([]map[string]any(nil), api.sandboxes[start:end]...)
			api.mu.Unlock()
			next := ""
			if end < len(api.sandboxes) {
				next = strconv.Itoa(end)
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"continue": next}, "items": items})
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/apis/agents.x-k8s.io/v1beta1/namespaces/"+tenantNS+"/sandboxes/"):
			n := api.inFlight.Add(1)
			defer api.inFlight.Add(-1)
			for {
				m := api.maxFlight.Load()
				if n <= m || api.maxFlight.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			name := strings.TrimPrefix(r.URL.Path, "/apis/agents.x-k8s.io/v1beta1/namespaces/"+tenantNS+"/sandboxes/")
			var options struct {
				Preconditions struct {
					UID string `json:"uid"`
				} `json:"preconditions"`
			}
			if json.NewDecoder(r.Body).Decode(&options) != nil || options.Preconditions.UID != "uid-"+name {
				w.WriteHeader(409)
				return
			}
			if api.throttle.Add(-1) >= 0 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			if name == api.failName {
				w.WriteHeader(500)
				return
			}
			api.mu.Lock()
			api.deleted[name] = true
			api.mu.Unlock()
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	api.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
	api.srv.StartTLS()
	t.Cleanup(api.srv.Close)
	return api
}

func janitorSandbox(i int, age time.Duration) map[string]any {
	name := fmt.Sprintf("sb-%05d", i)
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": tenantNS, "uid": "uid-" + name,
		"creationTimestamp": time.Now().Add(-age).UTC().Format(time.RFC3339)}}
}

func replicaPod(name, ip string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name}, "status": map[string]any{"phase": "Running", "podIP": ip}}
}

// activityServer is one proxy replica's admin listener.
func activityServer(t *testing.T, started time.Time, sandboxes ...SandboxActivity) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ActivityPath {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(ActivityReport{ReplicaStarted: started, RetentionSeconds: 86400, Sandboxes: sandboxes})
	}))
	t.Cleanup(s.Close)
	return s
}

type janitorFixture struct {
	j   *janitor
	api *fakeJanitorAPI
	out *bytes.Buffer
}

// newJanitor runs against the fake API with a replica per activity server,
// keyed by a fake Pod IP.
func newJanitor(t *testing.T, replicas map[string]*httptest.Server) *janitorFixture {
	t.Helper()
	f := newRelayFixture(t)
	api := newFakeJanitorAPI(t, f)
	for ip := range replicas {
		api.replicas = append(api.replicas, replicaPod("proxy-"+ip, ip))
	}
	c := JanitorConfig{Namespaces: []string{tenantNS}, IdleSeconds: 3600, DeleteConcurrency: 64, ListPageSize: 500,
		ProxyNamespace: "gatehouse-proxy", ProxyLabels: map[string]string{"app": "gatehouse-proxy"}, AdminPort: 8081,
		SandboxAPIVersion: "agents.x-k8s.io/v1beta1", ProxyAutoscaler: "gatehouse-proxy", ProxyDeployment: "gatehouse-proxy",
		Kubernetes: KubernetesConfig{APIURL: api.srv.URL, CAFile: f.c.Kubernetes.CAFile, ReviewerTokenFile: f.c.Kubernetes.ReviewerTokenFile}}
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	t2, _ := clientTLS(c.Kubernetes.CAFile, "")
	out := &bytes.Buffer{}
	j := &janitor{config: c, out: out, now: time.Now,
		client:  &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: t2, MaxIdleConnsPerHost: 256}},
		admin:   &http.Client{Timeout: 5 * time.Second},
		backoff: func(int, string) time.Duration { return time.Millisecond }}
	j.replicaURL = func(ip string) string {
		if s, ok := replicas[ip]; ok {
			return s.URL + ActivityPath
		}
		return "http://127.0.0.1:1" + ActivityPath
	}
	return &janitorFixture{j: j, api: api, out: out}
}

func (jf *janitorFixture) events(t *testing.T, name string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(jf.out.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["event"] == name {
			out = append(out, m)
		}
	}
	return out
}

// 12,000 Sandboxes over 24 pages: every idle one is deleted in one pass, by
// UID, with at most deleteConcurrency deletes in flight; used, young and
// leaving ones are kept.
func TestJanitorClearsTwelveThousandInOnePass(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	var recent []SandboxActivity
	for i := 0; i < 12000; i += 4 { // every fourth Sandbox was used 5 minutes ago, on one replica or the other
		recent = append(recent, SandboxActivity{Namespace: tenantNS, OwnerUID: fmt.Sprintf("uid-sb-%05d", i),
			LastSeen: time.Now().Add(-5 * time.Minute)})
	}
	jf := newJanitor(t, map[string]*httptest.Server{
		"10.0.0.1": activityServer(t, old, recent[:len(recent)/2]...),
		"10.0.0.2": activityServer(t, old, recent[len(recent)/2:]...),
	})
	for i := 0; i < 12000; i++ {
		age := 3 * time.Hour
		if i%4 == 1 {
			age = 10 * time.Minute // too young to be idle
		}
		s := janitorSandbox(i, age)
		if i%4 == 2 && i%8 == 2 {
			s["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
		}
		jf.api.sandboxes = append(jf.api.sandboxes, s)
	}
	jf.api.throttle.Store(200) // the API server throttles the first 200 deletes
	if e := jf.j.pass(context.Background()); e != nil {
		t.Fatal(e)
	}
	want := 0
	for i := 0; i < 12000; i++ {
		idle := i%4 == 3 || (i%4 == 2 && i%8 != 2)
		if idle {
			want++
		}
		if jf.api.deleted[fmt.Sprintf("sb-%05d", i)] != idle {
			t.Fatalf("sandbox %d: deleted %v, idle %v", i, !idle, idle)
		}
	}
	if len(jf.api.deleted) != want || jf.api.maxFlight.Load() > 64 || jf.api.lists.Load() != 24 {
		t.Fatalf("deleted %d of %d, max in flight %d, list pages %d", len(jf.api.deleted), want, jf.api.maxFlight.Load(), jf.api.lists.Load())
	}
	pass := jf.events(t, "janitor_pass")
	if len(pass) != 1 || pass[0]["deleted"] != float64(want) || pass[0]["sandboxes"] != float64(12000) {
		t.Fatalf("pass line %v", pass)
	}
}

// A fault deletes nothing and fails the run: a replica that does not answer,
// one whose retention is shorter than the idle time, no replica at all, or a
// scale record that cannot be read.
func TestJanitorDeletesNothingOnAFault(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	short := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ActivityReport{ReplicaStarted: old, RetentionSeconds: 600})
	}))
	t.Cleanup(short.Close)
	for name, replicas := range map[string]map[string]*httptest.Server{
		"silent replica":          {"10.0.0.1": activityServer(t, old), "10.0.0.9": nil},
		"short retention":         {"10.0.0.1": activityServer(t, old), "10.0.0.2": short},
		"no replica":              {},
		"unreadable scale record": {"10.0.0.1": activityServer(t, old)},
	} {
		t.Run(name, func(t *testing.T) {
			live := map[string]*httptest.Server{}
			for ip, s := range replicas {
				if s != nil {
					live[ip] = s
				}
			}
			jf := newJanitor(t, live)
			for ip, s := range replicas {
				if s == nil {
					jf.api.replicas = append(jf.api.replicas, replicaPod("proxy-"+ip, ip))
				}
			}
			if name == "unreadable scale record" {
				jf.api.scaleStatus = 403
			}
			jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour)}
			if e := jf.j.pass(context.Background()); e == nil || len(jf.api.deleted) != 0 {
				t.Fatalf("deleted %d, error %v", len(jf.api.deleted), e)
			}
		})
	}
}

// An expected pause deletes nothing, logs why and succeeds: a replica
// younger than the idle time, or a proxy autoscale or Deployment change
// within it.
func TestJanitorHoldsAfterAProxyChange(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	for reason, setup := range map[string]func(jf *janitorFixture){
		"proxy_replica_young":      func(*janitorFixture) {},
		"proxy_autoscaled":         func(jf *janitorFixture) { jf.api.scaled = time.Now().Add(-10 * time.Minute) },
		"proxy_deployment_changed": func(jf *janitorFixture) { jf.api.progressed = time.Now().Add(-10 * time.Minute) },
	} {
		t.Run(reason, func(t *testing.T) {
			started := old
			if reason == "proxy_replica_young" {
				started = time.Now().Add(-10 * time.Minute)
			}
			jf := newJanitor(t, map[string]*httptest.Server{"10.0.0.1": activityServer(t, old), "10.0.0.2": activityServer(t, started)})
			setup(jf)
			jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour)}
			if e := jf.j.pass(context.Background()); e != nil || len(jf.api.deleted) != 0 {
				t.Fatalf("deleted %d, error %v", len(jf.api.deleted), e)
			}
			if pass := jf.events(t, "janitor_pass"); len(pass) != 1 || pass[0]["held"] != reason {
				t.Fatalf("pass line %v", pass)
			}
		})
	}
	// Without the two names configured, neither record is read.
	jf := newJanitor(t, map[string]*httptest.Server{"10.0.0.1": activityServer(t, old)})
	jf.j.config.ProxyAutoscaler, jf.j.config.ProxyDeployment = "", ""
	jf.api.scaleStatus = 403
	jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour)}
	if e := jf.j.pass(context.Background()); e != nil || len(jf.api.deleted) != 1 {
		t.Fatalf("unconfigured scale records: deleted %d, error %v", len(jf.api.deleted), e)
	}
}

// Throttled retries are spread: never before Retry-After, at most twice it,
// and with no Retry-After anywhere from zero up to the exponential bound.
func TestJanitorBackoffJitters(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		d := defaultBackoff(0, "2")
		if d < 2*time.Second || d >= 4*time.Second {
			t.Fatalf("Retry-After 2: waited %v", d)
		}
		seen[d] = true
		if e := defaultBackoff(3, ""); e < 0 || e >= 2*time.Second {
			t.Fatalf("attempt 3: waited %v", e)
		}
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct waits in 200: no jitter", len(seen))
	}
}

// Dry run logs every Sandbox it would delete and deletes none.
func TestJanitorDryRun(t *testing.T) {
	jf := newJanitor(t, map[string]*httptest.Server{"10.0.0.1": activityServer(t, time.Now().Add(-2*time.Hour))})
	jf.j.config.DryRun = true
	for i := 0; i < 3; i++ {
		jf.api.sandboxes = append(jf.api.sandboxes, janitorSandbox(i, 3*time.Hour))
	}
	if e := jf.j.pass(context.Background()); e != nil || len(jf.api.deleted) != 0 || len(jf.events(t, "sandbox_would_delete")) != 3 {
		t.Fatalf("dry run: error %v, deleted %d, logged %d", e, len(jf.api.deleted), len(jf.events(t, "sandbox_would_delete")))
	}
}

// A delete the API refuses for any reason but throttling stops the pass.
func TestJanitorStopsOnAnError(t *testing.T) {
	jf := newJanitor(t, map[string]*httptest.Server{"10.0.0.1": activityServer(t, time.Now().Add(-2*time.Hour))})
	jf.j.config.DeleteConcurrency = 1
	for i := 0; i < 50; i++ {
		jf.api.sandboxes = append(jf.api.sandboxes, janitorSandbox(i, 3*time.Hour))
	}
	jf.api.failName = "sb-00010"
	if e := jf.j.pass(context.Background()); e == nil || len(jf.api.deleted) >= 50 || jf.api.deleted["sb-00010"] {
		t.Fatalf("error %v, deleted %d", e, len(jf.api.deleted))
	}
}

func TestJanitorConfigValidation(t *testing.T) {
	jf := newJanitor(t, nil)
	good := jf.j.config
	for name, change := range map[string]func(*JanitorConfig){
		"no namespaces":       func(c *JanitorConfig) { c.Namespaces = nil },
		"idle under a minute": func(c *JanitorConfig) { c.IdleSeconds = 59 },
		"no concurrency":      func(c *JanitorConfig) { c.DeleteConcurrency = 0 },
		"no page size":        func(c *JanitorConfig) { c.ListPageSize = 0 },
		"proxy as tenant":     func(c *JanitorConfig) { c.Namespaces = []string{"gatehouse-proxy"} },
		"no proxy labels":     func(c *JanitorConfig) { c.ProxyLabels = nil },
		"plain API":           func(c *JanitorConfig) { c.Kubernetes.APIURL = "http://x" },
		"core API version":    func(c *JanitorConfig) { c.SandboxAPIVersion = "v1" },
		"bad admin port":      func(c *JanitorConfig) { c.AdminPort = 0 },
		"bad autoscaler name": func(c *JanitorConfig) { c.ProxyAutoscaler = "Gatehouse_Proxy" },
		"bad deployment name": func(c *JanitorConfig) { c.ProxyDeployment = "gatehouse/proxy" },
	} {
		c := good
		c.Namespaces = append([]string(nil), good.Namespaces...)
		change(&c)
		if c.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The rendered config, with the proxy's autoscaler and Deployment named,
// loads.
func TestJanitorConfigLoadsTheScaleRecords(t *testing.T) {
	jf := newJanitor(t, nil)
	b, _ := json.Marshal(jf.j.config)
	if !bytes.Contains(b, []byte(`"proxyAutoscaler":"gatehouse-proxy"`)) || !bytes.Contains(b, []byte(`"proxyDeployment":"gatehouse-proxy"`)) {
		t.Fatalf("field names: %s", b)
	}
	path := t.TempDir() + "/janitor.json"
	writeTestFile(t, path, b)
	if c, e := LoadJanitorConfig(path); e != nil || c.ProxyAutoscaler != "gatehouse-proxy" || c.ProxyDeployment != "gatehouse-proxy" {
		t.Fatalf("load: %v %+v", e, c)
	}
}

// When every replica's report is durable, a replica's coming or going loses
// nothing: a young replica and a recent scale do not hold the pass, and the
// scale records are not read.
func TestJanitorTrustsDurableReports(t *testing.T) {
	durable := func(started time.Time) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(ActivityReport{ReplicaStarted: started, RetentionSeconds: 86400, Durable: true,
				Sandboxes: []SandboxActivity{{Namespace: tenantNS, OwnerUID: "uid-sb-00002", LastSeen: time.Now().Add(-time.Minute)}}})
		}))
		t.Cleanup(s.Close)
		return s
	}
	jf := newJanitor(t, map[string]*httptest.Server{"10.0.0.1": durable(time.Now().Add(-2 * time.Hour)), "10.0.0.2": durable(time.Now().Add(-time.Minute))})
	jf.api.scaleStatus = 403
	jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour), janitorSandbox(2, 3*time.Hour)}
	if e := jf.j.pass(context.Background()); e != nil || len(jf.api.deleted) != 1 || !jf.api.deleted["sb-00001"] {
		t.Fatalf("durable pass: deleted %v, error %v", jf.api.deleted, e)
	}
	// One replica-local report brings the holds back.
	jf = newJanitor(t, map[string]*httptest.Server{"10.0.0.1": durable(time.Now().Add(-2 * time.Hour)), "10.0.0.2": activityServer(t, time.Now().Add(-time.Minute))})
	jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour)}
	if e := jf.j.pass(context.Background()); e != nil || len(jf.api.deleted) != 0 || jf.events(t, "janitor_pass")[0]["held"] != "proxy_replica_young" {
		t.Fatalf("mixed reports: deleted %v, error %v", jf.api.deleted, e)
	}
}

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
}

const tenantNS = "developers-sandboxes"

func newFakeJanitorAPI(t *testing.T, f *relayFixture) *fakeJanitorAPI {
	t.Helper()
	api := &fakeJanitorAPI{deleted: map[string]bool{}}
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
func activityServer(t *testing.T, started time.Time, pods ...PodActivity) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ActivityPath {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(ActivityReport{ReplicaStarted: started, Pods: pods})
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
		SandboxAPIVersion: "agents.x-k8s.io/v1beta1",
		Kubernetes:        KubernetesConfig{APIURL: api.srv.URL, CAFile: f.c.Kubernetes.CAFile, ReviewerTokenFile: f.c.Kubernetes.ReviewerTokenFile}}
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
	var recent []PodActivity
	for i := 0; i < 12000; i += 4 { // every fourth Sandbox was used 5 minutes ago, on one replica or the other
		recent = append(recent, PodActivity{Namespace: tenantNS, PodUID: fmt.Sprintf("pod-%d", i), OwnerUID: fmt.Sprintf("uid-sb-%05d", i),
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

// Any doubt deletes nothing: a replica that does not answer, a replica
// younger than the idle time, or no replica at all.
func TestJanitorDeletesNothingInDoubt(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	for name, replicas := range map[string]map[string]*httptest.Server{
		"silent replica": {"10.0.0.1": activityServer(t, old), "10.0.0.9": nil},
		"young replica":  {"10.0.0.1": activityServer(t, old), "10.0.0.2": activityServer(t, time.Now().Add(-10*time.Minute))},
		"no replica":     {},
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
			jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour)}
			if e := jf.j.pass(context.Background()); e == nil || len(jf.api.deleted) != 0 {
				t.Fatalf("deleted %d, error %v", len(jf.api.deleted), e)
			}
		})
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
	} {
		c := good
		c.Namespaces = append([]string(nil), good.Namespaces...)
		change(&c)
		if c.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

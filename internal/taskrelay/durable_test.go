package taskrelay

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// activityBroker stands in for the broker's cross-cluster listener: CONNECT
// like the HTTP proxy, and the two proxy activity routes over a map, two rows
// to a page.
type activityBroker struct {
	srv        *httptest.Server
	caFile     string
	mu         sync.Mutex
	rows       map[string]SandboxActivity
	records    atomic.Int32
	failRead   atomic.Bool
	failRecord atomic.Bool
	// history is when the binding's history began; zero until a report.
	history time.Time
}

func newActivityBroker(t *testing.T) *activityBroker {
	t.Helper()
	b := &activityBroker{rows: map[string]SandboxActivity{}}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			c, buf, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			buf.WriteString("HTTP/1.1 200 OK\r\n\r\n")
			buf.Flush()
			io.Copy(c, buf)
		case r.Method == http.MethodPost && r.URL.Path == activityRecordPath && !b.failRecord.Load() && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "):
			var body struct{ Sandboxes []SandboxActivity }
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			b.mu.Lock()
			if b.history.IsZero() {
				b.history = time.Now().UTC()
			}
			for _, row := range body.Sandboxes {
				if have, ok := b.rows[row.OwnerUID]; !ok || row.LastSeen.After(have.LastSeen) {
					b.rows[row.OwnerUID] = row
				}
			}
			b.mu.Unlock()
			b.records.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == activityReadPath && !b.failRead.Load():
			var body struct{ After string }
			json.NewDecoder(r.Body).Decode(&body)
			b.mu.Lock()
			var owners []string
			for owner := range b.rows {
				if owner > body.After {
					owners = append(owners, owner)
				}
			}
			sort.Strings(owners)
			page := map[string]any{"retentionSeconds": 7200, "next": ""}
			if !b.history.IsZero() {
				page["historyStarted"] = b.history
			}
			var rows []SandboxActivity
			for i, owner := range owners {
				if i == 2 {
					page["next"] = owners[1]
					break
				}
				rows = append(rows, b.rows[owner])
			}
			b.mu.Unlock()
			page["sandboxes"] = rows
			json.NewEncoder(w).Encode(page)
		default:
			w.WriteHeader(503)
		}
	}))
	t.Cleanup(b.srv.Close)
	b.caFile = filepath.Join(t.TempDir(), "broker-ca.pem")
	writeTestFile(t, b.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.srv.Certificate().Raw}))
	return b
}

func (b *activityBroker) upstream(c UpstreamConfig) UpstreamConfig {
	u, _ := url.Parse(b.srv.URL)
	c.Address, c.CAFile = u.Host, b.caFile
	return c
}

func (b *activityBroker) row(owner string) (SandboxActivity, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.rows[owner]
	return r, ok
}

// With durable activity, the replica reports its Sandboxes' use to the
// broker, and its activity report merges in every replica's history from the
// broker, keeping the later time and the shorter retention. If the broker's
// view cannot be read, the report is this replica's alone and says so.
func TestDurableActivityOutlivesTheReplica(t *testing.T) {
	broker := newActivityBroker(t)
	departed := time.Now().Add(-5 * time.Minute).Truncate(time.Second).UTC()
	history := time.Now().Add(-3 * time.Hour).Truncate(time.Second).UTC()
	broker.history = history
	broker.rows["sandbox-departed"] = SandboxActivity{Namespace: "agent-sandboxes", OwnerUID: "sandbox-departed", LastSeen: departed}
	broker.rows["sandbox-pod-a"] = SandboxActivity{Namespace: "agent-sandboxes", OwnerUID: "sandbox-pod-a", LastSeen: time.Now().Add(-time.Hour)}
	for i := 0; i < 5; i++ {
		owner := "sandbox-other-" + string(rune('a'+i))
		broker.rows[owner] = SandboxActivity{Namespace: "agent-sandboxes", OwnerUID: owner, LastSeen: departed}
	}
	admin := freeAddress(t)
	sf := startSharedWith(t, false, false, func(c *FixedConfig) {
		c.AdminListen = admin
		c.Connect.Upstream = broker.upstream(c.Connect.Upstream)
		c.DurableActivity = &DurableActivityConfig{PushSeconds: 1}
	})
	c, b, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	defer c.Close()
	_ = b // the tunnel stays open
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if r, ok := broker.row("sandbox-pod-a"); ok && time.Since(r.LastSeen) < 5*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the replica did not report its Sandbox to the broker")
		}
	}
	report := readActivity(t, admin)
	if !report.Durable || report.RetentionSeconds != 7200 || len(report.Sandboxes) != 7 || !report.HistoryStarted.Equal(history) {
		t.Fatalf("durable report: durable %v, retention %d, %d Sandboxes", report.Durable, report.RetentionSeconds, len(report.Sandboxes))
	}
	if seen, _ := sandboxSeen(report, "sandbox-departed"); !seen.Equal(departed) {
		t.Fatalf("another replica's history: %v", seen)
	}
	if seen, _ := sandboxSeen(report, "sandbox-pod-a"); time.Since(seen) > 5*time.Second {
		t.Fatalf("the later time did not win: %v", seen)
	}
	broker.failRead.Store(true)
	if local := readActivity(t, admin); local.Durable || len(local.Sandboxes) != 1 || local.RetentionSeconds != 86400 || !local.HistoryStarted.IsZero() {
		t.Fatalf("unreadable broker view: %+v", local)
	}
}

// Only newer times are reported, a failed report is retried, and the last
// one goes out when the relay stops.
func TestDurableActivityReportsNewerTimesAndOnStop(t *testing.T) {
	broker := newActivityBroker(t)
	f := newRelayFixture(t)
	a := newActivity(time.Now(), time.Hour)
	d := &durable{activity: a, upstream: broker.upstream(f.upstream(t, "")), interval: time.Hour}
	// With nothing to report, the first report still starts the history.
	if e := d.push(context.Background()); e != nil || broker.records.Load() != 1 || broker.history.IsZero() {
		t.Fatalf("empty first report: %v", e)
	}
	if e := d.push(context.Background()); e != nil || broker.records.Load() != 1 {
		t.Fatal("an empty report was repeated")
	}
	now := time.Now().UTC()
	a.record("ns", "sb-1", now.Add(-time.Minute))
	if e := d.push(context.Background()); e != nil || broker.records.Load() != 2 {
		t.Fatalf("first report: %v", e)
	}
	if rows := a.pending(); len(rows) != 0 {
		t.Fatalf("accepted rows still pending: %v", rows)
	}
	a.record("ns", "sb-1", now.Add(-2*time.Minute)) // older: nothing new
	if len(a.pending()) != 0 {
		t.Fatal("an older time is pending")
	}
	a.record("ns", "sb-2", now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.run(ctx) }()
	cancel()
	<-done
	if r, ok := broker.row("sb-2"); !ok || !r.LastSeen.Equal(now) {
		t.Fatalf("the report on stop: %v %v", r, ok)
	}
	// The broker refuses: the row stays pending for the next report.
	broker.failRecord.Store(true)
	a.record("ns", "sb-3", now)
	if d.push(context.Background()) == nil || len(a.pending()) != 1 {
		t.Fatal("a refused report was marked accepted")
	}
}

// durableActivity needs the admin listener and the CONNECT upstream.
func TestDurableActivityValidation(t *testing.T) {
	sf := startShared(t, false)
	c := sf.f.c
	c.AdminListen = freeAddress(t)
	c.DurableActivity = &DurableActivityConfig{}
	if e := c.Validate(time.Now()); e != nil {
		t.Fatalf("valid: %v", e)
	}
	for name, mutate := range map[string]func(c *FixedConfig){
		"no admin listener": func(c *FixedConfig) { c.AdminListen = "" },
		"no CONNECT":        func(c *FixedConfig) { c.Connect = nil },
		"negative interval": func(c *FixedConfig) { c.DurableActivity = &DurableActivityConfig{PushSeconds: -1} },
		"over an hour":      func(c *FixedConfig) { c.DurableActivity = &DurableActivityConfig{PushSeconds: 3601} },
	} {
		m := c
		mutate(&m)
		if m.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

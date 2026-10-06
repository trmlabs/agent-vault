package taskrelay

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func readActivity(t *testing.T, address string) ActivityReport {
	t.Helper()
	resp, err := http.Get("http://" + address + ActivityPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var report ActivityReport
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&report) != nil {
		t.Fatalf("activity: %d", resp.StatusCode)
	}
	return report
}

func sandboxSeen(r ActivityReport, owner string) (time.Time, bool) {
	for _, a := range r.Sandboxes {
		if a.OwnerUID == owner {
			return a.LastSeen, true
		}
	}
	return time.Time{}, false
}

// The admin listener reports, per Sandbox, when it was last in use through
// this replica: its Pod's start, admission, and every second while a
// connection stays open. The entry outlives the Pod, and a replacement Pod's
// start counts as use of the same Sandbox.
func TestActivityRecordsUseBySandbox(t *testing.T) {
	admin := freeAddress(t)
	sf := startSharedWith(t, false, false, func(c *FixedConfig) { c.AdminListen = admin })
	before := readActivity(t, admin)
	started, ok := sandboxSeen(before, "sandbox-pod-a")
	if !ok || len(before.Sandboxes) != 1 || before.Sandboxes[0].Namespace != "agent-sandboxes" || before.RetentionSeconds != 86400 ||
		time.Since(started) < 50*time.Second || time.Since(started) > 2*time.Minute || before.ReplicaStarted.IsZero() {
		t.Fatalf("before any connection, the Pod's start: %+v", before)
	}
	c, b, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	<-sf.attested
	admitted, _ := sandboxSeen(readActivity(t, admin), "sandbox-pod-a")
	if time.Since(admitted) > 5*time.Second {
		t.Fatalf("after admission: %v", admitted)
	}
	// Held open with no traffic, the tunnel still counts as use.
	time.Sleep(2500 * time.Millisecond)
	if later, _ := sandboxSeen(readActivity(t, admin), "sandbox-pod-a"); !later.After(admitted) {
		t.Fatalf("an open connection did not count: %v then %v", admitted, later)
	}
	// The Pod is replaced (eviction, node loss): the old one goes, and the
	// Sandbox keeps its history.
	sf.api.send(t, "DELETED", sandboxPod("sandbox-a", "pod-a", "127.0.0.1"))
	if !tunnelCloses(t, c, b) {
		t.Fatal("tunnel stayed open")
	}
	last, ok := sandboxSeen(readActivity(t, admin), "sandbox-pod-a")
	if !ok || time.Since(last) > 5*time.Second {
		t.Fatalf("the Sandbox's history went with its Pod: %v %v", last, ok)
	}
	replacement := sandboxPod("sandbox-a2", "pod-a2", "127.0.0.3")
	replacement["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "sandbox-pod-a"
	replacement["status"].(map[string]any)["startTime"] = time.Now().Add(time.Second).UTC().Format(time.RFC3339)
	sf.api.send(t, "ADDED", replacement)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if seen, _ := sandboxSeen(readActivity(t, admin), "sandbox-pod-a"); seen.After(last) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the replacement Pod's start did not count")
		}
	}
}

// Entries past the retention time are dropped, and an earlier time never
// replaces a later one.
func TestActivityRetention(t *testing.T) {
	now := time.Now()
	a := newActivity(now, time.Hour)
	a.record("ns", "kept", now.Add(-30*time.Minute))
	a.record("ns", "kept", now.Add(-50*time.Minute))
	a.record("ns", "expired", now.Add(-61*time.Minute))
	r := a.report(now)
	if len(r.Sandboxes) != 1 || r.Sandboxes[0].OwnerUID != "kept" || !r.Sandboxes[0].LastSeen.Equal(now.Add(-30*time.Minute).UTC()) || r.RetentionSeconds != 3600 {
		t.Fatalf("report %+v", r)
	}
	if len(a.owners) != 1 {
		t.Fatalf("expired entry still held: %d", len(a.owners))
	}
}

// Only GET /v1/activity is served; every other path and method is 404.
func TestActivityListenerServesOneRoute(t *testing.T) {
	admin := freeAddress(t)
	startSharedWith(t, false, false, func(c *FixedConfig) { c.AdminListen = admin })
	readActivity(t, admin)
	for _, probe := range []struct{ method, path string }{
		{"POST", ActivityPath}, {"PUT", ActivityPath}, {"DELETE", ActivityPath}, {"HEAD", ActivityPath},
		{"GET", "/"}, {"GET", ActivityPath + "/x"}, {"GET", ActivityPath + "?pod=x"}, {"GET", "/v1/activity/"},
		{"GET", "/debug/pprof/"}, {"GET", "/metrics"}, {"GET", "/healthz"}, {"GET", "/v1/config"},
	} {
		req, _ := http.NewRequest(probe.method, "http://"+admin+probe.path, strings.NewReader(""))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s %s: %d", probe.method, probe.path, resp.StatusCode)
		}
	}
}

// adminListen is for a shared proxy only, on its own address.
func TestAdminListenValidation(t *testing.T) {
	f := newRelayFixture(t)
	c := f.c
	c.AdminListen = freeAddress(t)
	if c.Validate(time.Now()) == nil {
		t.Fatal("adminListen outside shared mode")
	}
	sf := startShared(t, false)
	shared := sf.f.c
	shared.AdminListen = shared.Connect.Listen
	if shared.Validate(time.Now()) == nil {
		t.Fatal("adminListen on the CONNECT address")
	}
	shared.AdminListen = "not-an-address"
	if shared.Validate(time.Now()) == nil {
		t.Fatal("adminListen with no port")
	}
}

// Retention needs the admin listener and lies between a minute and a year.
func TestActivityRetentionValidation(t *testing.T) {
	sf := startShared(t, false)
	c := sf.f.c
	c.AdminListen = freeAddress(t)
	for _, seconds := range []int64{60, 86400, 366 * 24 * 3600} {
		c.ActivityRetentionSeconds = seconds
		if e := c.Validate(time.Now()); e != nil {
			t.Fatalf("%d seconds refused: %v", seconds, e)
		}
	}
	for _, seconds := range []int64{-1, 59, 366*24*3600 + 1} {
		c.ActivityRetentionSeconds = seconds
		if c.Validate(time.Now()) == nil {
			t.Fatalf("%d seconds accepted", seconds)
		}
	}
	c.AdminListen, c.ActivityRetentionSeconds = "", 3600
	if c.Validate(time.Now()) == nil {
		t.Fatal("retention without the admin listener")
	}
}

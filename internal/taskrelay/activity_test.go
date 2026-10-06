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

// The admin listener reports when each agent Pod last used this replica:
// on admission, and every second while a connection stays open. A Pod that
// leaves is forgotten.
func TestActivityRecordsAdmissionAndOpenConnections(t *testing.T) {
	admin := freeAddress(t)
	sf := startSharedWith(t, false, false, func(c *FixedConfig) { c.AdminListen = admin })
	before := readActivity(t, admin)
	if len(before.Pods) != 0 || before.ReplicaStarted.IsZero() || time.Since(before.ReplicaStarted) > time.Minute {
		t.Fatalf("before any connection: %+v", before)
	}
	c, b, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	<-sf.attested
	first := readActivity(t, admin)
	if len(first.Pods) != 1 || first.Pods[0].PodUID != "pod-a" || first.Pods[0].OwnerUID != "sandbox-pod-a" ||
		first.Pods[0].Namespace != "agent-sandboxes" || time.Since(first.Pods[0].LastSeen) > 5*time.Second {
		t.Fatalf("after admission: %+v", first)
	}
	// Held open with no traffic, the tunnel still counts as use.
	time.Sleep(2500 * time.Millisecond)
	if later := readActivity(t, admin); !later.Pods[0].LastSeen.After(first.Pods[0].LastSeen) {
		t.Fatalf("an open connection did not count: %v then %v", first.Pods[0].LastSeen, later.Pods[0].LastSeen)
	}
	gone := sandboxPod("sandbox-a", "pod-a", "127.0.0.1")
	sf.api.send(t, "DELETED", gone)
	if !tunnelCloses(t, c, b) {
		t.Fatal("tunnel stayed open")
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(readActivity(t, admin).Pods) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a deleted Pod stayed in the report")
		}
		time.Sleep(50 * time.Millisecond)
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

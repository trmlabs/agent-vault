package taskrelay

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func runningContainer(name string) map[string]any {
	return map[string]any{"name": name, "restartCount": 0, "state": map[string]any{"running": map[string]any{"startedAt": "2026-01-01T00:00:00Z"}}}
}

func setContainerStatuses(t *testing.T, f *relayFixture, statuses ...map[string]any) {
	t.Helper()
	b, e := json.Marshal(statuses)
	if e != nil {
		t.Fatal(e)
	}
	f.containerStatuses.Store(json.RawMessage(b))
}

func TestContainerNameIsRequiredConfiguration(t *testing.T) {
	f := newRelayFixture(t)
	f.c.Connect = &ConnectConfig{Listen: "127.0.0.1:14443", Upstream: f.upstream(t, "127.0.0.1:25443"), AllowedTargets: []string{"approved.test:443"}}
	for _, name := range []string{"", "Worker", "worker/name", "worker_name", "-worker", "worker-", strings.Repeat("a", 64)} {
		c := f.c
		c.Sandbox.ContainerName = name
		if c.Validate(time.Now()) == nil {
			t.Fatalf("accepted container name %q", name)
		}
	}
	if e := f.c.Validate(time.Now()); e != nil {
		t.Fatal(e)
	}
}

func TestPairRequiresRunningTaskContainerWithoutReportedRestarts(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]any) []map[string]any
	}{
		{"missing", func(w map[string]any) []map[string]any { return nil }},
		{"duplicate", func(w map[string]any) []map[string]any { return []map[string]any{w, w} }},
		{"terminated", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"terminated": map[string]any{"exitCode": 0}}
			return []map[string]any{w}
		}},
		{"waiting", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"waiting": map[string]any{"reason": "ContainerCreating"}}
			return []map[string]any{w}
		}},
		{"missing-state", func(w map[string]any) []map[string]any { delete(w, "state"); return []map[string]any{w} }},
		{"missing-restart-count", func(w map[string]any) []map[string]any { delete(w, "restartCount"); return []map[string]any{w} }},
		{"null-restart-count", func(w map[string]any) []map[string]any { w["restartCount"] = nil; return []map[string]any{w} }},
		{"restarted", func(w map[string]any) []map[string]any { w["restartCount"] = 1; return []map[string]any{w} }},
		{"negative-restarts", func(w map[string]any) []map[string]any { w["restartCount"] = -1; return []map[string]any{w} }},
		{"missing-start-time", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"running": map[string]any{}}
			return []map[string]any{w}
		}},
		{"null-start-time", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"running": map[string]any{"startedAt": nil}}
			return []map[string]any{w}
		}},
		{"invalid-start-time", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"running": map[string]any{"startedAt": "bad"}}
			return []map[string]any{w}
		}},
		{"zero-start-time", func(w map[string]any) []map[string]any {
			w["state"] = map[string]any{"running": map[string]any{"startedAt": "0001-01-01T00:00:00Z"}}
			return []map[string]any{w}
		}},
		{"conflicting-state", func(w map[string]any) []map[string]any {
			w["state"].(map[string]any)["terminated"] = map[string]any{"exitCode": 0}
			return []map[string]any{w}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRelayFixture(t)
			v, e := newPairVerifier(f.c)
			if e != nil {
				t.Fatal(e)
			}
			defer v.client.CloseIdleConnections()
			if e = v.check(context.Background(), "127.0.0.1:1234"); e != nil {
				t.Fatal(e)
			}
			statuses := tt.change(runningContainer("worker"))
			// The Pod and its transport sidecar remain Running throughout every case.
			statuses = append(statuses, runningContainer("tunnel"))
			setContainerStatuses(t, f, statuses...)
			if v.check(context.Background(), "127.0.0.1:1234") == nil {
				t.Fatal("accepted invalid task container")
			}
		})
	}
}

func TestTaskContainerExitClosesEstablishedDatabaseStream(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "terminated"
		if restart {
			name = "restarted"
		}
		t.Run(name, func(t *testing.T) {
			f := newRelayFixture(t)
			backend := newBindingBackend(t, f, "database")
			binding := PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, backend.listener.Addr().String()), Database: "database", User: "workload", Placeholder: "public-placeholder"}
			f.c.PostgresBindings = []PostgresConfig{binding}
			f.start(t)
			client, _ := openBinding(t, f, binding)
			// The backend echoes; the relay passes whole frames.
			if _, e := client.Write(encodePGFrame('d', []byte{'x'})); e != nil {
				t.Fatal(e)
			}
			if typ, value, e := readPGFrame(client, 16); e != nil || typ != 'd' || string(value) != "x" {
				t.Fatal("positive stream control failed")
			}
			worker := runningContainer("worker")
			if restart {
				worker["restartCount"] = 1
			} else {
				worker["state"] = map[string]any{"terminated": map[string]any{"exitCode": 0}}
			}
			setContainerStatuses(t, f, worker, runningContainer("tunnel"))
			select {
			case <-f.done:
			case <-time.After(5 * time.Second):
				t.Fatal("task container loss did not stop relay")
			}
			if f.runError == nil {
				t.Fatal("withdrawal returned success")
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			_, e := client.Read(make([]byte, 1))
			if e == nil {
				t.Fatal("stream remained open")
			}
			if n, ok := e.(net.Error); ok && n.Timeout() {
				t.Fatal("stream did not close")
			}
			if c, e := net.DialTimeout("tcp", binding.Listen, time.Second); e == nil {
				c.Close()
				t.Fatal("listener still accepts work")
			}
			if backend.arrivals.Load() != 1 {
				t.Fatal("unexpected additional upstream admission")
			}
		})
	}
}

package httpcatalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// fakeKV answers like a Vault KV v2 mount holding one secret, in the state
// set, through the real Vault client so its handling of a 404 is covered.
type fakeKV struct {
	state  atomic.Value // string
	reads  atomic.Int32
	client *vaultapi.Client
}

func newFakeKV(t *testing.T) *fakeKV {
	t.Helper()
	kv := &fakeKV{}
	kv.state.Store("live v1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kv.reads.Add(1)
		if r.URL.Path != "/v1/gatehouse/data/vendors/example" {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		status, body := http.StatusOK, ""
		switch kv.state.Load().(string) {
		case "live v1":
			body = `{"data":{"data":{"key":"synthetic-key-one"},"metadata":{"version":1}}}`
		case "live v2":
			body = `{"data":{"data":{"key":"synthetic-key-two"},"metadata":{"version":2}}}`
		case "version deleted":
			status, body = http.StatusNotFound, `{"data":{"data":null,"metadata":{"deletion_time":"2026-10-09T18:00:00Z","destroyed":false,"version":1}}}`
		case "version destroyed":
			status, body = http.StatusNotFound, `{"data":{"data":null,"metadata":{"deletion_time":"","destroyed":true,"version":1}}}`
		case "secret deleted":
			status, body = http.StatusNotFound, `{"errors":[]}`
		case "field removed":
			body = `{"data":{"data":{"other":"synthetic-other"},"metadata":{"version":2}}}`
		case "value emptied":
			body = `{"data":{"data":{"key":""},"metadata":{"version":2}}}`
		case "sealed":
			status, body = http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`
		case "permission denied":
			status, body = http.StatusForbidden, `{"errors":["permission denied"]}`
		case "connection dropped":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	client, err := vaultapi.NewClient(&vaultapi.Config{Address: srv.URL, HttpClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("example-token")
	kv.client = client
	return kv
}

// A key deleted in Vault is refused within one minute, and the refusal is
// cached so a deleted destination does not cost a Vault read per request.
func TestDeletedKeyIsRefusedWithinOneMinute(t *testing.T) {
	ref := KeyRef{Mount: "gatehouse", Path: "vendors/example", Field: "key"}
	for _, state := range []string{"version deleted", "version destroyed", "secret deleted", "field removed", "value emptied"} {
		t.Run(state, func(t *testing.T) {
			kv := newFakeKV(t)
			now := time.Date(2026, 10, 9, 18, 0, 0, 0, time.UTC)
			keys := &Keys{Vault: kv.client.Logical(), Now: func() time.Time { return now }}
			get := func() (Secret, error) { return keys.Get(context.Background(), ref) }
			if s, err := get(); err != nil || s.Version != 1 {
				t.Fatalf("live key: v%d %v", s.Version, err)
			}

			kv.state.Store(state)
			now = now.Add(time.Minute) // the worst case: deleted just after a read
			if s, err := get(); !errors.Is(err, ErrKeyDeleted) || !errors.Is(err, ErrKeyUnavailable) || s.Value() != "" {
				t.Fatalf("deleted key served after a minute: v%d %v", s.Version, err)
			}
			reads := kv.reads.Load()
			for range 1000 {
				if _, err := get(); !errors.Is(err, ErrKeyDeleted) {
					t.Fatalf("refusal not cached: %v", err)
				}
			}
			if got := kv.reads.Load(); got != reads {
				t.Fatalf("1000 refused requests made %d Vault reads", got-reads)
			}

			// A later outage does not bring the deleted key back as stale.
			kv.state.Store("sealed")
			now = now.Add(time.Minute)
			if s, err := get(); err == nil || s.Value() != "" {
				t.Fatalf("deleted key served during an outage: v%d", s.Version)
			}

			// A key written again is served within the TTL.
			kv.state.Store("live v2")
			now = now.Add(time.Minute)
			if s, err := get(); err != nil || s.Version != 2 {
				t.Fatalf("new key not picked up: v%d %v", s.Version, err)
			}
		})
	}
}

// A Vault that does not answer keeps the cached key in use for MaxStale past
// its TTL, then requests fail without calling the key deleted.
func TestUnreachableVaultKeepsGracePeriod(t *testing.T) {
	ref := KeyRef{Mount: "gatehouse", Path: "vendors/example", Field: "key"}
	for _, state := range []string{"sealed", "permission denied", "connection dropped"} {
		t.Run(state, func(t *testing.T) {
			kv := newFakeKV(t)
			now := time.Date(2026, 10, 9, 18, 0, 0, 0, time.UTC)
			keys := &Keys{Vault: kv.client.Logical(), Now: func() time.Time { return now }}
			get := func() (Secret, error) { return keys.Get(context.Background(), ref) }
			if _, err := get(); err != nil {
				t.Fatal(err)
			}

			kv.state.Store(state)
			before := kv.reads.Load()
			now = now.Add(time.Minute + 5*time.Minute - time.Second) // TTL plus MaxStale, less a second
			if s, err := get(); err != nil || s.Version != 1 {
				t.Fatalf("grace period not honored: v%d %v", s.Version, err)
			}
			if kv.reads.Load() == before {
				t.Fatal("the stale key was served without trying Vault")
			}
			now = now.Add(2 * time.Second)
			if _, err := get(); !errors.Is(err, ErrKeyUnavailable) || errors.Is(err, ErrKeyDeleted) {
				t.Fatalf("after the grace period: %v", err)
			}

			// Vault back with the same key: served again.
			kv.state.Store("live v1")
			if s, err := get(); err != nil || s.Version != 1 {
				t.Fatalf("key not served once Vault answered: %v", err)
			}
		})
	}
}

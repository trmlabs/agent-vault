package taskrelay

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A failed Pod cache request names its class: DNS, timeout, connect, TLS or
// the HTTP status, and stays errDenied to every caller.
func TestSyncFailuresAreClassified(t *testing.T) {
	for name, tc := range map[string]struct {
		err   error
		class string
	}{
		"dns":     {&net.DNSError{Err: "no such host", Name: "kubernetes.default.svc", IsNotFound: true}, syncFailDNS},
		"timeout": {fmt.Errorf("Get: %w", context.DeadlineExceeded), syncFailTimeout},
		"tls":     {fmt.Errorf("Get: %w", x509.UnknownAuthorityError{}), syncFailTLS},
		"connect": {&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, syncFailConnect},
		"other":   {errors.New("something else"), syncFailOther},
	} {
		t.Run(name, func(t *testing.T) {
			s := classifyTransport(tc.err)
			if s.class != tc.class || !errors.Is(s, errDenied) {
				t.Fatalf("class %q, want %q; errDenied %v", s.class, tc.class, errors.Is(s, errDenied))
			}
		})
	}
	if s := classifyTransport(&net.DNSError{Name: "kubernetes.default.svc"}); s.host != "kubernetes.default.svc" {
		t.Fatalf("dns host %q", s.host)
	}
}

// A namespace that keeps failing the same way logs once, then once per
// interval with the count it held back; a change of class logs at once; and
// a sync that succeeds again logs once.
func TestSyncFailuresAreRateLimited(t *testing.T) {
	sink := captureLog(t)
	log := newRelayLog()
	var w syncWatch
	now := time.Unix(1_000_000, 0)
	for i := 0; i < 5; i++ {
		w.failed(log, "ns", &syncError{class: syncFailTimeout}, now.Add(time.Duration(i)*time.Second))
	}
	if lines := sink.lines(t, "pod_cache_sync_failed"); len(lines) != 1 || lines[0]["class"] != syncFailTimeout {
		t.Fatalf("repeats within the interval: %v", lines)
	}
	w.failed(log, "ns", &syncError{class: syncFailHTTP, status: 403}, now.Add(6*time.Second))
	lines := sink.lines(t, "pod_cache_sync_failed")
	if len(lines) != 2 || lines[1]["class"] != syncFailHTTP || lines[1]["status"] != float64(403) || lines[1]["suppressed"] != float64(4) {
		t.Fatalf("a change of class: %v", lines)
	}
	w.failed(log, "ns", &syncError{class: syncFailHTTP, status: 403}, now.Add(6*time.Second+syncLogInterval))
	if lines := sink.lines(t, "pod_cache_sync_failed"); len(lines) != 3 || lines[2]["failures"] != float64(7) {
		t.Fatalf("after the interval: %v", lines)
	}
	w.synced(log, "ns", now.Add(2*syncLogInterval))
	w.synced(log, "ns", now.Add(3*syncLogInterval))
	if lines := sink.lines(t, "pod_cache_sync_restored"); len(lines) != 1 || lines[0]["failures"] != float64(7) {
		t.Fatalf("restored: %v", lines)
	}
}

// End to end through the cache's own client: a refused API call, an
// unverifiable certificate and an unresolvable name each log their class,
// and the API token appears in no log line.
func TestSyncFailureLogsNeverCarryTheToken(t *testing.T) {
	const token = "synthetic-api-token-c0ffee-must-never-be-logged"
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeTestFile(t, tokenFile, []byte(token))
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden: "+r.Header.Get("Authorization"), http.StatusForbidden)
	}))
	t.Cleanup(forbidden.Close)
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(untrusted.Close)
	for name, tc := range map[string]struct {
		url    string
		client *http.Client
		class  string
	}{
		"http 403": {forbidden.URL, &http.Client{}, syncFailHTTP},
		"tls":      {untrusted.URL, &http.Client{}, syncFailTLS},
		"dns":      {"https://gatehouse-sync-test.invalid", &http.Client{}, syncFailDNS},
	} {
		t.Run(name, func(t *testing.T) {
			sink := captureLog(t)
			c := &podCache{config: &SharedConfig{Profiles: map[string]string{"developers": "p"}},
				k8s:    KubernetesConfig{APIURL: tc.url, ReviewerTokenFile: tokenFile},
				client: tc.client, now: time.Now, pods: map[string]*agentPod{}, byIP: map[netip.Addr]map[string]struct{}{},
				inSync: map[string]bool{}, lostAt: map[string]time.Time{}, activity: newActivity(time.Now(), time.Hour), log: newRelayLog()}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); c.run(ctx) }()
			waitUntil(t, "a sync failure line", func() bool { return len(sink.lines(t, "pod_cache_sync_failed")) > 0 })
			cancel()
			<-done
			line := sink.lines(t, "pod_cache_sync_failed")[0]
			if line["class"] != tc.class || line["namespace"] != "developers" {
				t.Fatalf("line %v, want class %s", line, tc.class)
			}
			sink.mu.Lock()
			all := sink.b.String()
			sink.mu.Unlock()
			if strings.Contains(all, token) || strings.Contains(all, "Bearer") {
				t.Fatalf("the token reached the log: %s", all)
			}
		})
	}
}

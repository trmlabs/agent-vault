package pgproxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestDurableLeaseUnrelatedCleanupDoesNotDelayRenewal(t *testing.T) {
	_, st, _ := durableFixture(t)
	origin, _ := url.Parse(os.Getenv("VAULT_ADDR"))
	upstream := httputil.NewSingleHostReverseProxy(origin)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-accessor" {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "unrelated-orphan") {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
					w.WriteHeader(403)
				case <-r.Context().Done():
				}
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		upstream.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("VAULT_ADDR", proxy.URL)
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{RetryInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	lease, err := m.Mint(context.Background(), "vault", &DatabaseService{Name: "healthy", Mount: "database", Role: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddDatabaseCleanup(context.Background(), m.owner, store.DatabaseCleanup{Accessor: "unrelated-orphan", Binding: "vault/broken"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("background cleanup did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	renewed := make(chan error, 1)
	go func() { _, err := m.Renew(ctx, lease.ID, time.Minute); renewed <- err }()
	var renewalErr error
	received := false
	select {
	case renewalErr = <-renewed:
		received = true
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	if !received {
		renewalErr = <-renewed
	}
	if renewalErr != nil {
		t.Fatalf("healthy renewal missed its deadline during unrelated cleanup: %v", renewalErr)
	}
}

func TestDurableLeaseCloseHonorsDeadlineWhileIssuanceLockHeld(t *testing.T) {
	client, st, _ := durableFixture(t)
	m := newDurableForTest(t, client, st)
	m.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	closed := make(chan error, 1)
	go func() { closed <- m.Close(ctx) }()
	select {
	case err := <-closed:
		if err != context.DeadlineExceeded {
			t.Errorf("close returned %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Error("close ignored deadline waiting for issuance")
	}
	m.mu.Unlock()
}

func TestDurableLeaseRevokeTimeoutRetiresSessionAndQuarantinesBinding(t *testing.T) {
	client, st, f := durableFixture(t)
	m := newDurableForTest(t, client, st)
	svc := &DatabaseService{Name: "db", Mount: "database", Role: "reader"}
	lease, err := m.Mint(context.Background(), "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failRevoke = true
	f.mu.Unlock()
	m.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = m.Revoke(ctx, lease.ID)
	cancel()
	m.mu.Unlock()
	if err != context.DeadlineExceeded {
		t.Fatalf("expected cleanup deadline, got %v", err)
	}
	m.activeMu.Lock()
	_, active := m.active[lease.ID]
	m.activeMu.Unlock()
	if active {
		t.Fatal("disconnected session remained active after cleanup timeout")
	}
	if _, err = m.Mint(context.Background(), "vault", svc); err == nil {
		t.Fatal("binding admitted while retired lease cleanup failed")
	}
	records, err := st.ListDatabaseCleanup(context.Background())
	if err != nil || len(records) != 1 || records[0].LeaseID != lease.ID {
		t.Fatal("retired lease lost its durable cleanup record", err)
	}
	f.mu.Lock()
	f.failRevoke = false
	f.mu.Unlock()
	fresh, err := m.Mint(context.Background(), "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Revoke(context.Background(), fresh.ID); err != nil {
		t.Fatal(err)
	}
}

package pgproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

type durableVaultFixture struct {
	mu           sync.Mutex
	issued       int
	next         int
	failRevoke   bool
	loseResponse bool
	live         map[string]bool
	journal      *store.SQLStore
	mintStarted  chan struct{}
	mintRelease  chan struct{}
}

func durableFixture(t *testing.T) (*hashicorp.Client, *store.SQLStore, *durableVaultFixture) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &durableVaultFixture{live: make(map[string]bool), journal: st}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			write(map[string]any{"data": map[string]any{"id": "parent"}})
		case r.URL.Path == "/v1/auth/token/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.next++
			ref := fmt.Sprintf("ref-%d", f.next)
			write(map[string]any{"auth": map[string]any{"accessor": ref, "client_token": ref, "policies": body["policies"], "lease_duration": 60, "renewable": false}})
		case strings.Contains(r.URL.Path, "/creds/"):
			ref := r.Header.Get("X-Vault-Token")
			records, err := st.ListDatabaseCleanup(r.Context())
			if err != nil {
				t.Error(err)
			}
			persisted := false
			for _, record := range records {
				if record.Accessor == ref {
					persisted = true
				}
			}
			if !persisted {
				t.Error("mint happened before durable cleanup reference")
			}
			f.issued++
			f.live[ref] = true
			if f.mintStarted != nil {
				close(f.mintStarted)
				select {
				case <-f.mintRelease:
				case <-r.Context().Done():
					return
				}
			}
			if f.loseResponse {
				_, _ = w.Write([]byte("interrupted-json"))
				return
			}
			write(map[string]any{"lease_id": "lease-" + ref, "lease_duration": 30, "renewable": true, "data": map[string]any{"username": "user-" + ref, "password": "synthetic-private-password"}})
		case r.URL.Path == "/v1/auth/token/revoke-accessor":
			if f.failRevoke {
				w.WriteHeader(403)
				write(map[string]any{"errors": []string{"synthetic cleanup unavailable"}})
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			delete(f.live, body["accessor"])
			w.WriteHeader(204)
		case strings.HasPrefix(r.URL.Path, "/v1/sys/leases/revoke/"):
			if f.failRevoke {
				w.WriteHeader(403)
				write(map[string]any{"errors": []string{"synthetic cleanup unavailable"}})
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["sync"] != true {
				t.Error("database revoke was not synchronous")
			}
			delete(f.live, strings.TrimPrefix(r.URL.Path, "/v1/sys/leases/revoke/lease-"))
			w.WriteHeader(204)
		case r.URL.Path == "/v1/sys/leases/lookup":
			w.WriteHeader(400)
			write(map[string]any{"errors": []string{"invalid lease"}})
		case r.URL.Path == "/v1/sys/leases/renew":
			write(map[string]any{"lease_duration": 120})
		default:
			t.Error("unexpected Vault API", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "parent")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return client, st, f
}

func newDurableForTest(t *testing.T, client *hashicorp.Client, st *store.SQLStore) *DurableLeaseMinter {
	t.Helper()
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{RetryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Close(ctx)
	})
	return m
}

func TestDurableLeaseCleanupFailureBlocksBindingAndPreservesOtherSession(t *testing.T) {
	client, st, f := durableFixture(t)
	m := newDurableForTest(t, client, st)
	ctx := context.Background()
	svc := &DatabaseService{Name: "db", Mount: "database", Role: "reader"}
	first, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failRevoke = true
	f.mu.Unlock()
	if err = m.Revoke(ctx, first.ID); err == nil {
		t.Fatal("cleanup outage accepted")
	}
	if _, err = m.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("unreconciled binding reopened")
	}
	f.mu.Lock()
	if f.issued != 2 || !f.live[m.active[second.ID].accessor] {
		t.Error("cleanup changed independent session")
	}
	f.failRevoke = false
	f.mu.Unlock()
	third, err := m.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Revoke(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err = m.Revoke(ctx, third.ID); err != nil {
		t.Fatal(err)
	}
	records, err := st.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 0 {
		t.Fatal("cleanup records remain", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.live) != 0 {
		t.Fatal("live fixture credentials remain")
	}
}

func TestDurableLeaseLostIssuanceResponseRecoversOnRestart(t *testing.T) {
	client, st, f := durableFixture(t)
	m := newDurableForTest(t, client, st)
	ctx := context.Background()
	svc := &DatabaseService{Name: "db", Mount: "database", Role: "reader"}
	f.mu.Lock()
	f.loseResponse = true
	f.failRevoke = true
	f.mu.Unlock()
	if _, err := m.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("interrupted response accepted")
	}
	if err := m.Close(ctx); err == nil {
		t.Fatal("cleanup outage accepted")
	}
	records, err := st.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 1 {
		t.Fatal("lost unknown issuance recovery record", err)
	}
	m2 := newDurableForTest(t, client, st)
	if _, err := m2.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("restart admitted unreconciled binding")
	}
	f.mu.Lock()
	if f.issued != 1 {
		t.Error("ambiguous issuance retried")
	}
	f.failRevoke = false
	f.loseResponse = false
	f.mu.Unlock()
	if _, err = m2.Mint(ctx, "vault", svc); err == nil {
		t.Fatal("unknown issuance automatically cleared")
	}
	if err = m2.ConfirmDatabaseCleanup(ctx, records[0].Accessor, "test: observed fixture credential absence"); err != nil {
		t.Fatal(err)
	}
	lease, err := m2.Mint(ctx, "vault", svc)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if len(f.live) != 1 {
		t.Error("unknown issued credential not removed")
	}
	f.mu.Unlock()
	if err = m2.Revoke(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDurableLeaseConfirmationCannotRaceIssuance(t *testing.T) {
	client, st, f := durableFixture(t)
	m := newDurableForTest(t, client, st)
	f.mintStarted = make(chan struct{})
	f.mintRelease = make(chan struct{})
	type result struct {
		lease *Lease
		err   error
	}
	issued := make(chan result, 1)
	go func() {
		lease, err := m.Mint(context.Background(), "vault", &DatabaseService{Name: "db", Mount: "database", Role: "reader"})
		issued <- result{lease, err}
	}()
	select {
	case <-f.mintStarted:
	case <-time.After(time.Second):
		t.Fatal("issuance not reached")
	}
	records, err := st.ListDatabaseCleanup(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatal("missing issuance intent", err)
	}
	confirmed := make(chan error, 1)
	go func() {
		confirmed <- m.ConfirmDatabaseCleanup(context.Background(), records[0].Accessor, "operator evidence prepared during issuance")
	}()
	select {
	case <-confirmed:
		t.Fatal("confirmation overlapped issuance")
	case <-time.After(30 * time.Millisecond):
	}
	close(f.mintRelease)
	got := <-issued
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := <-confirmed; err == nil {
		t.Fatal("known lease was manually cleared")
	}
	records, err = st.ListDatabaseCleanup(context.Background())
	if err != nil || len(records) != 1 || records[0].LeaseID != got.lease.ID {
		t.Fatal("issued lease disappeared from recovery journal", err)
	}
	if err = m.Revoke(context.Background(), got.lease.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDurableLeaseSingletonAndAuthorityLoss(t *testing.T) {
	client, st, _ := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if other, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{}); err == nil {
		_ = other.Close(context.Background())
		t.Fatal("two brokers acquired journal")
	}
	if err := st.ReleaseDatabaseCleanupOwner(context.Background(), m.owner); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.AuthorityDone():
	case <-time.After(2 * time.Second):
		t.Fatal("owner loss did not stop authority")
	}
	if _, err = m.Mint(context.Background(), "vault", &DatabaseService{Name: "db", Mount: "database", Role: "reader"}); err == nil {
		t.Fatal("minted after authority lost")
	}
}

func TestDurableLeaseRenewalIsBoundedByChildExpiry(t *testing.T) {
	client, st, _ := durableFixture(t)
	m := newDurableForTest(t, client, st)
	lease, err := m.Mint(context.Background(), "vault", &DatabaseService{Name: "db", Mount: "database", Role: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	expiry, err := m.Renew(context.Background(), lease.ID, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !expiry.Equal(m.active[lease.ID].expires) {
		t.Fatal("lease renewal escaped child-token maximum lifetime")
	}
}

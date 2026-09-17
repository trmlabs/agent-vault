package requestlog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func auditAttempt() Attempt {
	return Attempt{VaultID: "vault-1", ActorType: "workload", ActorID: "actor-1", WorkloadID: "pod-1", Destination: "api.example.test:443", Service: "example", MappingIDs: []string{"mapping-1"}, Method: "POST", Decision: "allow"}
}

func TestDurableAuditRestartAndStorageRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sink := NewDurable(s)
	id, err := sink.Begin(ctx, auditAttempt())
	if err != nil {
		t.Fatal(err)
	}
	done, err := sink.Begin(ctx, auditAttempt())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Finish(ctx, done, Outcome{Result: "completed", Status: 201}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Begin(ctx, auditAttempt()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("closed store: %v", err)
	}
	if err := sink.Finish(ctx, id, Outcome{Result: "completed", Status: 200}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("finish closed store: %v", err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.GetProxyAudit(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "unknown" || r.Status != 0 || r.FinishedAt != nil {
		t.Fatalf("lost uncertainty after restart: %+v", r)
	}
	r, err = s.GetProxyAudit(ctx, done)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "completed" || r.Status != 201 || r.FinishedAt == nil || r.WorkloadID != "pod-1" {
		t.Fatalf("lost completion: %+v", r)
	}
	sink = NewDurable(s)
	denial := auditAttempt()
	denial.Decision = "deny"
	denied, err := sink.Begin(ctx, denial)
	if err != nil {
		t.Fatalf("recovery begin: %v", err)
	}
	if err := sink.Finish(ctx, denied, Outcome{Result: "denied", Status: 403}); err != nil {
		t.Fatal(err)
	}
	r, err = s.GetProxyAudit(ctx, denied)
	if err != nil || r.Decision != "deny" || r.Outcome != "denied" {
		t.Fatalf("denial: %+v %v", r, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("audit database accessible to other users: %v", info.Mode())
	}
}

func TestDurableAuditConcurrentRequests(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sink := NewDurable(s)
	ctx := context.Background()
	var wg sync.WaitGroup
	ids := make(chan string, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := sink.Begin(ctx, auditAttempt())
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id
			if err := sink.Finish(ctx, id, Outcome{Result: "completed", Status: 200}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("duplicate request ID")
		}
		seen[id] = true
		r, err := s.GetProxyAudit(ctx, id)
		if err != nil || r.Outcome != "completed" {
			t.Fatalf("record: %+v %v", r, err)
		}
	}
	if len(seen) != 32 {
		t.Fatalf("record count: %d", len(seen))
	}
}

type failingAuditStore struct{}

func (failingAuditStore) InsertProxyAudit(context.Context, store.ProxyAudit) error {
	return errors.New("database error including secret-canary")
}
func (failingAuditStore) CompleteProxyAudit(context.Context, string, string, int) error {
	return errors.New("database error including secret-canary")
}

func TestDurableAuditRejectsUnsafeMetadataAndRedactsStorageErrors(t *testing.T) {
	for _, destination := range []string{"https://example.test/path?token=secret-canary", "user:secret-canary@example.test", "example.test/path/secret-canary", "example.test?secret-canary", "example.test\nsecret-canary"} {
		a := auditAttempt()
		a.Destination = destination
		if _, err := NewDurable(failingAuditStore{}).Begin(context.Background(), a); !errors.Is(err, ErrInvalidAudit) {
			t.Errorf("unsafe destination accepted: %v", err)
		}
	}
	a := auditAttempt()
	a.MappingIDs = []string{"mapping\nsecret-canary"}
	if _, err := NewDurable(failingAuditStore{}).Begin(context.Background(), a); !errors.Is(err, ErrInvalidAudit) {
		t.Fatal(err)
	}
	_, err := NewDurable(failingAuditStore{}).Begin(context.Background(), auditAttempt())
	if !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("storage detail leaked: %v", err)
	}
	err = NewDurable(failingAuditStore{}).Finish(context.Background(), "id", Outcome{Result: "completed", Status: 200})
	if !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("finish detail leaked: %v", err)
	}
	if _, err := NewDurable(nil).Begin(context.Background(), auditAttempt()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatal(err)
	}
}

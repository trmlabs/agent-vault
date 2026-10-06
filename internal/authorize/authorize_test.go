package authorize

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

type oneToken struct{}

func (oneToken) Verify(_ context.Context, token string) (runnerid.Session, error) {
	if token != "alice" {
		return runnerid.Session{}, runnerid.ErrInvalid
	}
	return runnerid.Session{Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa", Expires: time.Now().Add(time.Hour)}, nil
}

type failingBinder struct{}

func (failingBinder) BindRunnerSession(context.Context, string, string, time.Time) (string, error) {
	return "", errors.New("store down")
}

var claude = httpcatalog.Pool{Identity: "claude-session", CCPoolID: "ccpool_abc"}

// A runner session token is pinned to the first Pod that presents it.
func TestSessionIsPinnedToItsFirstPod(t *testing.T) {
	b := &authorizetest.MemBinder{}
	ctx := context.Background()
	if who, refusal := Resolve(ctx, claude, "alice", Claims{Pod: "pod-a"}, oneToken{}, b); refusal != "" || who.Subject != "sso|alice" {
		t.Fatalf("first use on pod A: %q %+v", refusal, who)
	}
	if _, refusal := Resolve(ctx, claude, "alice", Claims{Pod: "pod-a"}, oneToken{}, b); refusal != "" {
		t.Fatalf("recheck on pod A refused: %q", refusal)
	}
	if who, refusal := Resolve(ctx, claude, "alice", Claims{Pod: "pod-b"}, oneToken{}, b); refusal != "session_pod_mismatch" || who.Kind != "none" {
		t.Fatalf("same token on pod B: %q %+v", refusal, who)
	}
}

func TestSessionWithoutABindingIsRefused(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		pod string
		b   Binder
	}{
		"no binder":      {"pod-a", nil},
		"no pod":         {"", &authorizetest.MemBinder{}},
		"binder failing": {"pod-a", failingBinder{}},
	} {
		if _, refusal := Resolve(ctx, claude, "alice", Claims{Pod: c.pod}, oneToken{}, c.b); refusal != "session_unbindable" {
			t.Errorf("%s: %q, want session_unbindable", name, refusal)
		}
	}
	// No session at all needs no binding: no person, T0 only.
	if who, refusal := Resolve(ctx, claude, "", Claims{Pod: "pod-a"}, oneToken{}, nil); refusal != "" || who.Kind != "none" {
		t.Fatalf("no session: %q %+v", refusal, who)
	}
}

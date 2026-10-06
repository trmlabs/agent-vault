package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// cursorRuns maps a token to the run it names; any other token is invalid.
type cursorRuns map[string]runnerid.Session

func (cursorRuns) Verify(context.Context, string) (runnerid.Session, error) {
	return runnerid.Session{}, runnerid.ErrUnverifiable
}

func (c cursorRuns) VerifyCursor(_ context.Context, token string) (runnerid.Session, error) {
	s, ok := c[token]
	if !ok {
		return runnerid.Session{}, runnerid.ErrInvalid
	}
	s.TokenSHA256, s.Expires = "sha-"+token, time.Now().Add(5*time.Minute)
	return s, nil
}

var (
	cursorPool = httpcatalog.Pool{Identity: "cursor-session"}
	runs       = cursorRuns{
		"alice-1": {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-1"},
		"alice-2": {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-2"},
		"bob":     {Kind: runnerid.KindPerson, Subject: "bob@example.com", Owner: "user:2", Run: "bc-3"},
		"no-mail": {Kind: runnerid.KindNone, Owner: "user:3", Run: "bc-4"},
		"team":    {Kind: runnerid.KindNone, Run: "bc-5"},
	}
)

func TestCursorRunNamesItsPerson(t *testing.T) {
	who, refusal := Resolve(context.Background(), cursorPool, "alice-1", "pod-a", runs, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || who.Subject != "alice@example.com" || who.TokenSHA256 != "sha-alice-1" {
		t.Fatalf("%q %+v", refusal, who)
	}
}

// A worker Pod serves one owner in its life: the same person's next run is
// fine, anyone else's is refused, and a token copied to another Pod is too.
func TestCursorPodIsPinnedToItsFirstOwner(t *testing.T) {
	b := &authorizetest.MemBinder{}
	ctx := context.Background()
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "pod-a", runs, b); refusal != "" {
		t.Fatalf("alice's first run: %q", refusal)
	}
	if _, refusal := Resolve(ctx, cursorPool, "alice-2", "pod-a", runs, b); refusal != "" {
		t.Fatalf("alice's second run on her Pod: %q", refusal)
	}
	if who, refusal := Resolve(ctx, cursorPool, "bob", "pod-a", runs, b); refusal != "session_pod_owner" || who.Kind != "none" {
		t.Fatalf("bob on alice's Pod: %q %+v", refusal, who)
	}
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "pod-b", runs, b); refusal != "session_pod_mismatch" {
		t.Fatalf("alice's token on another Pod: %q", refusal)
	}
	// A run with no mappable person still owns its Pod; it just names nobody.
	if who, refusal := Resolve(ctx, cursorPool, "no-mail", "pod-c", runs, b); refusal != "" || who.Kind != "none" {
		t.Fatalf("no email: %q %+v", refusal, who)
	}
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "pod-c", runs, b); refusal != "session_pod_mismatch" {
		t.Fatalf("alice's pinned token on a third Pod: %q", refusal)
	}
	if _, refusal := Resolve(ctx, cursorPool, "team", "pod-d", runs, b); refusal != "session_token" {
		t.Fatalf("no owner: %q", refusal)
	}
}

func TestCursorRefusals(t *testing.T) {
	ctx := context.Background()
	b := &authorizetest.MemBinder{}
	if _, refusal := Resolve(ctx, cursorPool, "forged", "pod-a", runs, b); refusal != "session_token" {
		t.Errorf("invalid token: %q", refusal)
	}
	// A broker with only a Claude verifier cannot verify a Cursor run.
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "pod-a", oneToken{}, b); refusal != "session_unverifiable" {
		t.Errorf("Claude-only verifier: %q", refusal)
	}
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "pod-a", runnerid.Verifiers{}, b); refusal != "session_unverifiable" {
		t.Errorf("no Cursor verifier: %q", refusal)
	}
	// A Cursor token on a Claude pool goes to the Claude verifier and fails.
	if _, refusal := Resolve(ctx, claude, "alice-1", "pod-a", runs, b); refusal != "session_unverifiable" {
		t.Errorf("Cursor token on a Claude pool: %q", refusal)
	}
	// No token: no person, T0 only.
	if who, refusal := Resolve(ctx, cursorPool, "", "pod-a", runs, nil); refusal != "" || who.Kind != "none" {
		t.Errorf("no token: %q %+v", refusal, who)
	}
	if _, refusal := Resolve(ctx, cursorPool, "alice-1", "", runs, b); refusal != "session_unbindable" {
		t.Errorf("no Pod: %q", refusal)
	}
	// A session on a pool whose requester is not a session is refused.
	if _, refusal := Resolve(ctx, httpcatalog.Pool{}, "alice-1", "pod-a", runs, b); refusal != "session_unexpected" {
		t.Errorf("pool without a session requester: %q", refusal)
	}
}

// Package authorize is the one place both protocol adapters decide who stands
// behind a request and whether that requester may use a catalog entry: the
// lesser of the pool's tier ceiling and the verified person's entitlements.
package authorize

import (
	"context"

	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Verifier checks a Claude runner session token.
type Verifier interface {
	Verify(context.Context, string) (runnerid.Session, error)
}

// Requester is who stands behind a request. TokenSHA256 identifies the runner
// session token without keeping it.
type Requester struct {
	Kind        string // person, agent, workload or none
	Subject     string
	TokenSHA256 string
}

// Resolve derives the requester for a pool from the session token the sidecar
// relayed (empty when none). It returns a refusal code when a presented token
// is invalid, was issued for another runner pool, or arrives on a pool that
// takes no session: a bad token is refused even for T0, never silently
// ignored. A Claude-session pool with no session has no person: T0 only.
func Resolve(ctx context.Context, pool httpcatalog.Pool, session string, v Verifier) (Requester, string) {
	who := Requester{Kind: "none"}
	// Only a Claude-session pool's sidecar relays a session. One arriving on
	// any other pool is a misconfigured or forged channel, never ignored.
	if session != "" && pool.Identity != "claude-session" {
		return who, "session_unexpected"
	}
	switch pool.Identity {
	case "workload":
		who.Kind = "workload"
	case "claude-session":
		if session == "" {
			return who, ""
		}
		if v == nil {
			return who, "session_unverifiable"
		}
		s, err := v.Verify(ctx, session)
		if err != nil {
			return who, "session_token"
		}
		who.TokenSHA256 = s.TokenSHA256
		if !s.InPool(pool.CCPoolID) {
			return who, "session_pool"
		}
		who.Kind, who.Subject = string(s.Kind), s.Subject
	}
	return who, ""
}

// Decide applies the entitlement decision for one entry.
func Decide(ctx context.Context, cache *entitlement.Cache, pool httpcatalog.Pool, entry httpcatalog.Entry, who Requester) entitlement.Decision {
	return entitlement.Decide(ctx, cache, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, entitlement.Requester{Kind: who.Kind, Subject: who.Subject})
}

// Package authorize is the one place both protocol adapters decide who stands
// behind a request and whether that requester may use a catalog entry: the
// lesser of the pool's tier ceiling and the verified person's entitlements.
package authorize

import (
	"context"
	"time"

	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Verifier checks a Claude runner session token.
type Verifier interface {
	Verify(context.Context, string) (runnerid.Session, error)
}

// Binder pins a runner session to the first Pod that presents it, across
// every broker replica, and returns the Pod it is pinned to. The pin lasts
// until the token expires.
type Binder interface {
	BindRunnerSession(ctx context.Context, tokenSHA256, pod string, expires time.Time) (string, error)
}

// Requester is who stands behind a request. TokenSHA256 identifies the runner
// session token without keeping it.
type Requester struct {
	Kind        string // person, agent, workload or none
	Subject     string
	TokenSHA256 string
}

// Resolve derives the requester for a pool from the session token the sidecar
// relayed (empty when none), as the pool's harness profile says. It returns a
// refusal code when a presented token is invalid, was issued for another
// runner pool, or arrives on a profile whose requester is not a session: a
// bad token is refused even for T0, never silently ignored. A session-jwt
// profile with no session has no person: T0 only.
//
// A session token is a bearer credential, so it is pinned to the first Pod
// that presents it: the same token from another Pod is refused
// (session_pod_mismatch), and without a binder or a Pod the session is
// refused (session_unbindable).
func Resolve(ctx context.Context, pool httpcatalog.Pool, session, pod string, v Verifier, b Binder) (Requester, string) {
	who := Requester{Kind: "none"}
	requester := pool.Profile().RequesterKind()
	// Only a session-jwt sidecar relays a session. One arriving on any other
	// profile is a misconfigured or forged channel, never ignored.
	if session != "" && requester != httpcatalog.RequesterSessionJWT {
		return who, "session_unexpected"
	}
	switch requester {
	case "":
		// Pool authorization: a workload pool's fixed entitlements, or none.
		if pool.Identity == "workload" {
			who.Kind = "workload"
		}
	case httpcatalog.RequesterSessionJWT:
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
		if b == nil || pod == "" {
			return who, "session_unbindable"
		}
		bound, err := b.BindRunnerSession(ctx, s.TokenSHA256, pod, s.Expires)
		if err != nil {
			return who, "session_unbindable"
		}
		if bound != pod {
			return who, "session_pod_mismatch"
		}
		who.Kind, who.Subject = string(s.Kind), s.Subject
	default:
		// A requester kind this broker cannot verify. The catalog refuses
		// such a profile at load; this keeps the decision closed regardless.
		return who, "requester_unverifiable"
	}
	return who, ""
}

// Decide applies the entitlement decision for one entry.
func Decide(ctx context.Context, cache *entitlement.Cache, pool httpcatalog.Pool, entry httpcatalog.Entry, who Requester) entitlement.Decision {
	return entitlement.Decide(ctx, cache, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, entitlement.Requester{Kind: who.Kind, Subject: who.Subject})
}

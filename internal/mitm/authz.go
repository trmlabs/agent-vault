package mitm

import (
	"context"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// SessionHeader carries the Claude runner's session token from the in-Pod
// sidecar on the CONNECT request. The sidecar sets it; a worker cannot, since
// the sidecar forwards only a fixed set of CONNECT headers.
const SessionHeader = "Gatehouse-Session"

type sessionTokenKey struct{}

func withSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionTokenKey{}, token)
}

func sessionToken(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenKey{}).(string)
	return token
}

// authorize applies the authorization model to one matched catalog entry:
// the lesser of the pool's tier ceiling and the verified requester's live
// entitlements. It fills the audit event and returns a refusal code, or "".
func (p *Proxy) authorize(ctx context.Context, scope *brokercore.ProxyScope, entry *httpcatalog.Entry, event *auditchain.Event) string {
	a := p.adapter
	catalog := a.Catalog.Current()
	pool, _ := catalog.Pool(scope.Pool) // undefined pools: no identity, ceiling T0
	who := entitlement.Requester{Kind: "none"}
	switch pool.Identity {
	case "workload":
		who.Kind = "workload"
	case "claude-session":
		if token := sessionToken(ctx); token != "" {
			if a.Runner == nil {
				return "session_unverifiable"
			}
			session, err := a.Runner.Verify(ctx, token)
			if err != nil {
				return "session_token"
			}
			event.TokenSHA256 = session.TokenSHA256
			if !session.InPool(pool.CCPoolID) {
				return "session_pool"
			}
			who.Kind, who.Subject = string(session.Kind), session.Subject
		}
	}
	event.RequesterKind = who.Kind
	if who.Kind == string(runnerid.KindPerson) || who.Kind == string(runnerid.KindAgent) {
		event.Requester = who.Subject
	}
	d := entitlement.Decide(ctx, a.Entitlements, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, who)
	event.Tier, event.Decision, event.RequesterOID = d.Tier, d.Outcome, d.ObjectID
	event.Groups = strings.Join(d.Groups, ",")
	event.CacheAgeSec = int64(d.CacheAge.Seconds())
	if !d.Allowed {
		return d.Outcome
	}
	return ""
}

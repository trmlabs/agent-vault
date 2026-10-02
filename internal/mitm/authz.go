package mitm

import (
	"context"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
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

// authorize applies the authorization model to one matched catalog entry and
// fills the audit event. It returns a refusal code, or "".
func (p *Proxy) authorize(ctx context.Context, scope *brokercore.ProxyScope, entry *httpcatalog.Entry, event *auditchain.Event) string {
	a := p.adapter
	pool, _ := a.Catalog.Current().Pool(scope.Pool) // undefined pools: no identity, ceiling T0
	var verifier authorize.Verifier
	if a.Runner != nil {
		verifier = a.Runner
	}
	who, refusal := authorize.Resolve(ctx, pool, sessionToken(ctx), verifier)
	event.TokenSHA256, event.RequesterKind = who.TokenSHA256, who.Kind
	if refusal != "" {
		return refusal
	}
	if who.Kind == "person" || who.Kind == "agent" {
		event.Requester = who.Subject
	}
	d := authorize.Decide(ctx, a.Entitlements, pool, *entry, who)
	event.Tier, event.Decision, event.RequesterOID = d.Tier, d.Outcome, d.ObjectID
	event.Groups = strings.Join(d.Groups, ",")
	event.CacheAgeSec = int64(d.CacheAge.Seconds())
	if !d.Allowed {
		return d.Outcome
	}
	return ""
}

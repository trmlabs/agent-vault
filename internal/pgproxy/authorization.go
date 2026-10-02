package pgproxy

import (
	"context"
	"net/netip"
	"time"
)

// authorizationLoop bounds the lifetime of an already-open session after token
// revocation/expiry, grant removal, or a binding change. Store unavailability
// fails closed. Capacity changes alone affect admission, not existing sessions.
func (b *Broker) authorizationLoop(ctx context.Context, token, hint, requested string, scope AgentScope, svc DatabaseService, terminate func(), peer netip.Addr) {
	defer func() {
		if recover() != nil {
			terminate()
		}
	}()
	ticker := time.NewTicker(b.opts.AuthorizationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		checkCtx, cancel := context.WithTimeout(ctx, b.opts.AuthorizationTimeout)
		// A dependency must honor context, but cannot postpone terminating access
		// simply by returning late. A fired watchdog cannot revive the session.
		watchdog := time.AfterFunc(b.opts.AuthorizationTimeout, terminate)
		current, err := b.renewalAuthenticator(peer).Authenticate(checkCtx, token, hint)
		valid := err == nil && current != nil && current.ActorID == scope.ActorID && current.VaultID == scope.VaultID && current.WorkloadID == scope.WorkloadID
		if valid {
			next, resolveErr := b.opts.Databases.ResolveDatabase(checkCtx, *current, requested)
			valid = resolveErr == nil && next != nil && sameBinding(svc, *next)
		}
		stopped := watchdog.Stop()
		valid = valid && stopped && checkCtx.Err() == nil
		cancel()
		if !valid {
			if ctx.Err() == nil {
				b.logger.Warn("pgproxy: authorization no longer confirmed; terminating session", "service", svc.Name, "actor", scope.ActorID)
			}
			terminate()
			return
		}
	}
}

func sameBinding(a, b DatabaseService) bool {
	a.MaxConns, b.MaxConns = 0, 0
	return a == b
}

// peerAuth adapts a PeerAuthenticator to the plain interface for one connection.
type peerAuth struct {
	auth    PeerAuthenticator
	peer    netip.Addr
	renewal bool
}

func (p peerAuth) Authenticate(ctx context.Context, token, hint string) (*AgentScope, error) {
	return p.auth.AuthenticatePeer(ctx, token, hint, p.peer, p.renewal)
}

// authenticator binds admission to the connection's peer when the configured
// authenticator supports it; otherwise it is the plain token check.
func (b *Broker) authenticator(peer netip.Addr) AgentAuthenticator {
	if auth, ok := b.opts.Auth.(PeerAuthenticator); ok && peer.IsValid() {
		return peerAuth{auth: auth, peer: peer}
	}
	return b.opts.Auth
}

func (b *Broker) renewalAuthenticator(peer netip.Addr) AgentAuthenticator {
	if auth, ok := b.opts.Auth.(PeerAuthenticator); ok && peer.IsValid() {
		return peerAuth{auth: auth, peer: peer, renewal: true}
	}
	return b.opts.Auth
}

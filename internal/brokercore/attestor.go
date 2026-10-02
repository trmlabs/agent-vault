package brokercore

import (
	"context"
	"net/netip"
)

// Attestor admits a worker by a projected, Pod-bound service-account token and
// the network address the connection actually came from. Every protocol
// adapter uses it, so the identity decision is made once for all of them.
//
// Attest verifies the token locally against the cluster's signing keys
// (audience, expiry, issuer, Pod claims), then requires peer to be the same
// live, Running Pod of an approved pool, inside its deadline. It returns the
// pool agent as AgentID, the Pod UID as WorkloadID, the vault, and NotAfter,
// the Pod's deadline, at which adapters must end the session. It fails closed
// and never returns a partial scope. peer comes from the accepted connection
// (or a PROXY header from a loopback TLS terminator), never from a client field.
type Attestor interface {
	Attest(ctx context.Context, token string, peer netip.Addr) (*ProxyScope, error)
}

// Reattestor rechecks an open session: the same Pod checks as Attest, but the
// original token's expiry is accepted, because a session or tunnel outlives
// its ten-minute token. Adapters use it for rechecks when the Attestor has it.
type Reattestor interface {
	Reattest(ctx context.Context, token string, peer netip.Addr) (*ProxyScope, error)
}

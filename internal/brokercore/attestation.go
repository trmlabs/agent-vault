package brokercore

import "context"

// AttestationHeader carries a shared proxy's attestation of the agent Pod
// behind a CONNECT request. Only a proxy-attested binding accepts it; any
// other identity presenting one is refused.
const AttestationHeader = "Gatehouse-Attestation"

type attestationKey struct{}

// WithAttestation carries the attestation a connection presented (encoded as
// the proxy sent it) to the Attestor, for admission and every recheck.
func WithAttestation(ctx context.Context, attestation string) context.Context {
	return context.WithValue(ctx, attestationKey{}, attestation)
}

// AttestationFrom returns the connection's attestation, or "".
func AttestationFrom(ctx context.Context) string {
	a, _ := ctx.Value(attestationKey{}).(string)
	return a
}

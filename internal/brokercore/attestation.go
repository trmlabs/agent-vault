package brokercore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
)

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

// maxAttestationHeader bounds what AttestedSandbox decodes; the verifier
// applies the same bound.
const maxAttestationHeader = 4096

var sandboxUID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// AttestedSandbox returns the controller UID (the Sandbox) an attestation
// names, without verifying it, or "" when it names none. It only keys
// pre-authentication rate limits on the cross-cluster listener, where every
// sandbox behind one shared proxy arrives from the proxy's address; the
// attestation itself is verified at admission.
func AttestedSandbox(attestation string) string {
	if attestation == "" || len(attestation) > maxAttestationHeader {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(attestation)
	if err != nil {
		return ""
	}
	var a struct {
		OwnerUID string `json:"ownerUID"`
	}
	if json.Unmarshal(b, &a) != nil || !sandboxUID.MatchString(a.OwnerUID) {
		return ""
	}
	return a.OwnerUID
}

// AttestationFrom returns the connection's attestation, or "".
func AttestationFrom(ctx context.Context) string {
	a, _ := ctx.Value(attestationKey{}).(string)
	return a
}

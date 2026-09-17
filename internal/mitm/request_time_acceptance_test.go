//go:build realvault && credentialproxyacceptance

package mitm

import "testing"

// This gate verifies fresh request-time Vault resolution with no synchronized
// local credential copy. It covers both proxy ingress forms; strict release
// format and TLS-only enforcement have separate tests.
// The fixture proves a permitted placeholder request before denial checks.
func TestRealVault_RequestTimeResolution(t *testing.T) {
	runVaultFreshnessFixture(t, true)
}

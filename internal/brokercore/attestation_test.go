package brokercore

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAttestedSandboxReadsOnlyTheOwnerUID(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	if got := AttestedSandbox(enc(`{"namespace":"n","ownerUID":"sandbox-uid-1","podUID":"p"}`)); got != "sandbox-uid-1" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"", "not base64!", enc(`{"ownerUID":""}`), enc(`{"ownerUID":"a b"}`), enc(`[1]`), strings.Repeat("A", 5000)} {
		if got := AttestedSandbox(bad); got != "" {
			t.Errorf("%.20q: %q", bad, got)
		}
	}
}

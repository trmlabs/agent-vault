package pgproxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// attestationAuth records the attestation each identity check saw.
type attestationAuth struct {
	fakePeerAuth
	mu       sync.Mutex
	attested []string
}

func (a *attestationAuth) AuthenticatePeer(ctx context.Context, token, hint string, peer netip.Addr, renewal bool) (*AgentScope, error) {
	a.mu.Lock()
	a.attested = append(a.attested, brokercore.AttestationFrom(ctx))
	a.mu.Unlock()
	return a.fakePeerAuth.AuthenticatePeer(ctx, token, hint, peer, renewal)
}

func (a *attestationAuth) seenAttestations() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.attested...)
}

const attestation = "eyJuYW1lc3BhY2UiOiJhZ2VudC1zYW5kYm94ZXMifQ"

// A shared proxy's attestation line reaches every identity check, admission
// and recheck, and the session line after it still reaches the resolver.
func TestAttestationPreambleReachesEveryIdentityCheck(t *testing.T) {
	r := &sessionResolver{}
	r.want.Store(runnerToken)
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	r.svc = &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}
	auth := &attestationAuth{}
	_, addr := startBroker(t, Options{Auth: auth, Databases: r, Leases: &fakeMinter{lease: lease},
		TrustProxyHeader: true, AuthorizationInterval: 50 * time.Millisecond})
	conn, err := openSession(t, addr, header("10.200.0.7")+"GHATTS1 "+attestation+"\nGHSESS1 "+runnerToken+"\n")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, 2*time.Second, func() bool {
		auth.fakePeerAuth.mu.Lock()
		defer auth.fakePeerAuth.mu.Unlock()
		return auth.renewals >= 1 && len(r.calls()) >= 2
	}, "no recheck ran")
	for _, got := range auth.seenAttestations() {
		if got != attestation {
			t.Fatalf("identity check saw attestation %q", got)
		}
	}
	for _, got := range r.calls() {
		if got != runnerToken {
			t.Fatalf("resolver saw session %q", got)
		}
	}
}

func TestAttestationPreambleParsing(t *testing.T) {
	for name, c := range map[string]struct {
		stream, session, attestation string
		ok                           bool
	}{
		"attestation only":         {"GHATTS1 abc\nXXXXXXXX", "", "abc", true},
		"attestation then session": {"GHATTS1 abc\nGHSESS1 a.b.c\n", "a.b.c", "abc", true},
		"neither":                  {"XXXXXXXXrest", "", "", true},
		"empty attestation":        {"GHATTS1 \n", "", "", false},
		"attestation with a space": {"GHATTS1 a b\n", "", "", false},
		"session before attestation, second line is startup": {"GHSESS1 a.b.c\nGHATTS1 abc\n", "a.b.c", "", true},
	} {
		client, server := net.Pipe()
		go func() { _, _ = client.Write([]byte(c.stream)); _ = client.Close() }()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		session, att, _, err := readSessionPreamble(server)
		_ = server.Close()
		if (err == nil) != c.ok || (c.ok && (session != c.session || att != c.attestation)) {
			t.Errorf("%s: session %q attestation %q err %v", name, session, att, err)
		}
	}
}

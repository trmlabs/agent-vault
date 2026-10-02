package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

type cmdTestKeys struct{ secret []byte }

func (k cmdTestKeys) Current(context.Context) (auditchain.Key, error) {
	return auditchain.NewKey(1, k.secret)
}

type cmdTestSigner struct{ private ed25519.PrivateKey }

func (s cmdTestSigner) Sign(_ context.Context, input []byte) (string, error) {
	return "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, input)), nil
}

func TestAuditVerifyExitStatus(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x5a}, 32) // synthetic
	var trail bytes.Buffer
	chain, err := auditchain.New(context.Background(), auditchain.Options{Out: &trail, Replica: "broker-0", Keys: cmdTestKeys{secret}, Signer: cmdTestSigner{private}})
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Record(auditchain.Event{Event: auditchain.EventSessionOpen, Pool: "pool", PodUID: "pod", Binding: "vault/core", Session: "s1", Outcome: "admitted"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifier := auditchain.Verifier{HMACKey: func(int) ([]byte, error) { return secret, nil }, PublicKeys: map[int]ed25519.PublicKey{1: public}}
	var out bytes.Buffer
	if err := runAuditVerify(strings.NewReader(trail.String()), &out, verifier); err != nil || !strings.Contains(out.String(), "findings=0") {
		t.Fatalf("clean trail: %v %s", err, out.String())
	}
	for name, input := range map[string]string{
		"edited": strings.Replace(trail.String(), `"outcome":"admitted"`, `"outcome":"closed"`, 1),
		"empty":  "",
	} {
		out.Reset()
		var exit *ExitCodeError
		if err := runAuditVerify(strings.NewReader(input), &out, verifier); !errors.As(err, &exit) || exit.Code != 1 {
			t.Fatalf("%s trail accepted: %v %s", name, err, out.String())
		}
		if strings.Contains(out.String(), base64.StdEncoding.EncodeToString(secret)) {
			t.Fatal("key material printed")
		}
	}
}

func TestBrokerAuditChainSettings(t *testing.T) {
	t.Setenv("AGENT_VAULT_AUDIT_CHAIN", "")
	if chain, err := brokerAuditChain(context.Background(), nil, func(string) string { return "" }); chain != nil || err != nil {
		t.Fatalf("disabled chain started: %v", err)
	}
	t.Setenv("AGENT_VAULT_AUDIT_CHAIN", "1")
	for _, env := range []map[string]string{
		{},
		{"AGENT_VAULT_AUDIT_HMAC_PATH": "gatehouse/audit-hmac"},
		{"AGENT_VAULT_AUDIT_TRANSIT_KEY": "gatehouse-audit"},
		{"AGENT_VAULT_AUDIT_HMAC_PATH": "gatehouse/audit-hmac", "AGENT_VAULT_AUDIT_TRANSIT_KEY": "gatehouse-audit"}, // no Vault client
	} {
		if _, err := brokerAuditChain(context.Background(), nil, func(k string) string { return env[k] }); err == nil {
			t.Fatalf("incomplete audit settings accepted: %v", env)
		}
	}
}

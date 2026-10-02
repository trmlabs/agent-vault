//go:build realvault

package auditchain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Requires VAULT_ADDR and VAULT_TOKEN for a disposable Vault with KV version 2
// at secret/ and Transit at transit/. It writes synthetic keys only.
func TestRealVault_ChainRotatesAndVerifies(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("set VAULT_ADDR and VAULT_TOKEN")
	}
	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	path := "audit-test-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	writeKey := func() {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Logical().WriteWithContext(ctx, "secret/data/"+path, map[string]interface{}{"data": map[string]interface{}{"key": base64.StdEncoding.EncodeToString(secret)}}); err != nil {
			t.Fatal(err)
		}
	}
	writeKey()
	if _, err := client.Logical().WriteWithContext(ctx, "transit/keys/"+path, map[string]interface{}{"type": "ed25519"}); err != nil {
		t.Fatal(err)
	}
	keys := KVKeys{Vault: client.Logical(), Mount: "secret", Path: path, Field: "key"}
	signer := TransitSigner{Vault: client.Logical(), Mount: "transit", Key: path}
	var out bytes.Buffer
	chain, err := New(ctx, Options{Out: &out, Replica: "broker-0", Keys: keys, Signer: signer, Boots: newMemBoots()})
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Record(Event{Event: EventSessionOpen, Pool: "pool", PodUID: "pod", Binding: "vault/core", Session: "s1", Outcome: "admitted"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	writeKey()
	if _, err := client.Logical().WriteWithContext(ctx, "transit/keys/"+path+"/rotate", nil); err != nil {
		t.Fatal(err)
	}
	if err := chain.RefreshKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err := chain.Record(Event{Event: EventSessionClose, Pool: "pool", PodUID: "pod", Binding: "vault/core", Session: "s1", Outcome: "closed"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	public, err := signer.PublicKeys(ctx)
	if err != nil || len(public) != 2 {
		t.Fatalf("public keys: %d %v", len(public), err)
	}
	v := Verifier{HMACKey: func(version int) ([]byte, error) { return keys.Version(ctx, version) }, PublicKeys: public, MaxUnsigned: time.Minute}
	report, err := v.Verify(strings.NewReader(out.String()))
	if err != nil || len(report.Findings) != 0 || report.Rows != 6 {
		t.Fatalf("report %+v %v\n%s", report, err, out.String())
	}
	if !strings.Contains(out.String(), `"signature":"vault:v2:`) || !strings.Contains(out.String(), `"keyVersion":2`) {
		t.Fatal("rotated keys not used")
	}
	tampered := strings.Replace(out.String(), `"outcome":"closed"`, `"outcome":"admitted"`, 1)
	if report, _ := v.Verify(strings.NewReader(tampered)); len(report.Findings) == 0 {
		t.Fatal("tampered real-Vault trail verified")
	}
}

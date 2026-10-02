package auditchain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// fakeVault serves KV v2 and Transit ed25519 with synthetic keys.
type fakeVault struct {
	hmac    map[int][]byte
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	signs   int
}

func newFakeVault(t *testing.T) (*fakeVault, *vaultapi.Client) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeVault{hmac: map[int][]byte{1: bytes.Repeat([]byte{0x11}, 32), 2: bytes.Repeat([]byte{0x22}, 32)}, private: private, public: public}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(data map[string]any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/gatehouse/audit-hmac":
			version := len(f.hmac)
			if v := r.URL.Query().Get("version"); v != "" {
				version = int(v[0] - '0')
			}
			key, ok := f.hmac[version]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			write(map[string]any{"data": map[string]any{"key": base64.StdEncoding.EncodeToString(key)}, "metadata": map[string]any{"version": version}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/gatehouse-audit":
			var body struct{ Input string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			input, _ := base64.StdEncoding.DecodeString(body.Input)
			f.signs++
			write(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, input))})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/gatehouse-audit":
			write(map[string]any{"type": "ed25519", "keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(f.public)}}})
		default:
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	config := vaultapi.DefaultConfig()
	config.Address = srv.URL
	client, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("synthetic-test-token")
	return f, client
}

// The production adapters drive a chain end to end, and the verifier checks
// it using only historical key reads and the exported public key.
func TestVaultBackedChainVerifies(t *testing.T) {
	fake, client := newFakeVault(t)
	keys := KVKeys{Vault: client.Logical(), Mount: "secret", Path: "gatehouse/audit-hmac", Field: "key"}
	signer := TransitSigner{Vault: client.Logical(), Mount: "transit", Key: "gatehouse-audit"}
	key, err := keys.Current(context.Background())
	if err != nil || key.Version != 2 {
		t.Fatalf("current key: %v %v", key, err)
	}
	var out bytes.Buffer
	chain, err := New(context.Background(), Options{Out: &out, Replica: "broker-0", Keys: keys, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Record(Event{Event: EventDenied, Outcome: "authentication"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Checkpoint(context.Background()); err != nil || fake.signs != 1 {
		t.Fatalf("checkpoint: %v signs=%d", err, fake.signs)
	}
	public, err := signer.PublicKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{HMACKey: func(version int) ([]byte, error) { return keys.Version(context.Background(), version) }, PublicKeys: public, MaxUnsigned: time.Minute}
	report, err := v.Verify(strings.NewReader(out.String()))
	if err != nil || len(report.Findings) != 0 || report.Rows != 3 {
		t.Fatalf("report %+v %v", report, err)
	}
	if strings.Contains(out.String(), base64.StdEncoding.EncodeToString(fake.hmac[2])) {
		t.Fatal("HMAC key in output")
	}
}

func TestVaultAdaptersFailWithoutDisclosure(t *testing.T) {
	_, client := newFakeVault(t)
	for _, k := range []KVKeys{
		{Vault: client.Logical(), Mount: "secret", Path: "missing", Field: "key"},
		{Vault: client.Logical(), Mount: "secret", Path: "gatehouse/audit-hmac", Field: "absent"},
		{Vault: client.Logical(), Mount: "secret", Path: "../escape", Field: "key"},
		{Mount: "secret", Path: "gatehouse/audit-hmac", Field: "key"},
	} {
		if _, err := k.Current(context.Background()); err == nil || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "ERERER") {
			t.Fatalf("unexpected result for %+v: %v", k.Path, err)
		}
	}
	keys := KVKeys{Vault: client.Logical(), Mount: "secret", Path: "gatehouse/audit-hmac", Field: "key"}
	if _, err := keys.Version(context.Background(), 9); err == nil {
		t.Fatal("missing version returned a key")
	}
	if _, err := (TransitSigner{Vault: client.Logical(), Mount: "transit", Key: "other"}).Sign(context.Background(), []byte("x")); err == nil {
		t.Fatal("denied signing succeeded")
	}
}

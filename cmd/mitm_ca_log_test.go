package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
)

// memoryCAStore keeps the CA's root in memory, so the test can read back the
// encrypted key the CA saved.
type memoryCAStore struct{ state *ca.CAStateRecord }

func (m *memoryCAStore) GetCAState(context.Context) (*ca.CAStateRecord, error) { return m.state, nil }
func (m *memoryCAStore) SetCAState(_ context.Context, s *ca.CAStateRecord) error {
	m.state = s
	return nil
}

func caLogLines(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatalf("log line %q: %v", raw, err)
		}
		if line["event"] == "mitm-ca" {
			lines = append(lines, line)
		}
	}
	return lines
}

// The broker logs its public interception root once in credential-proxy
// mode, exactly as it serves it, and never anything of its key.
func TestInterceptionCALoggedOnlyInCredentialProxyMode(t *testing.T) {
	masterKey := bytes.Repeat([]byte{7}, 32)
	for _, credentialProxy := range []bool{true, false} {
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		store := &memoryCAStore{}
		root, err := newInterceptionCA(masterKey, ca.Options{Store: store}, logger, credentialProxy)
		if err != nil {
			t.Fatal(err)
		}
		lines := caLogLines(t, &logs)
		if !credentialProxy {
			if len(lines) != 0 {
				t.Fatalf("CA logged outside credential-proxy mode: %v", lines)
			}
			continue
		}
		if len(lines) != 1 {
			t.Fatalf("want one mitm-ca line, got %d", len(lines))
		}
		logged, _ := lines[0]["pem"].(string)
		if logged != string(root.RootPEM()) {
			t.Fatal("logged PEM differs from the PEM the broker serves")
		}
		block, rest := pem.Decode([]byte(logged))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("logged PEM is not exactly one certificate: %q", logged)
		}
		sum := sha256.Sum256(block.Bytes)
		if lines[0]["sha256"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("sha256 %v does not match the certificate's DER", lines[0]["sha256"])
		}
		// No key material, in any encoding the log could carry.
		keyDER, err := crypto.Decrypt(store.state.RootKeyCT, store.state.RootKeyNonce, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		all := logs.String()
		for _, secret := range []string{"PRIVATE KEY", string(keyDER), base64.StdEncoding.EncodeToString(keyDER), hex.EncodeToString(keyDER),
			base64.StdEncoding.EncodeToString(store.state.RootKeyCT), string(store.state.RootKeyCT)} {
			if strings.Contains(all, secret) {
				t.Fatal("the log carries the CA's key material")
			}
		}
	}
}

// A CA that fails to initialize logs nothing.
func TestInterceptionCAFailureLogsNothing(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := newInterceptionCA(make([]byte, 7), ca.Options{Store: &memoryCAStore{}}, logger, true); err == nil {
		t.Fatal("a short master key initialized the CA")
	}
	if logs.Len() != 0 {
		t.Fatalf("a failed CA init logged %q", logs.String())
	}
}

// Anything but a single certificate is never logged as one.
func TestInterceptionCALogRefusesOtherPEM(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	two := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{2}})...)
	logInterceptionCA(logger, two)
	if strings.Contains(logs.String(), "PRIVATE KEY") || strings.Contains(logs.String(), `"pem"`) {
		t.Fatalf("a non-certificate PEM was logged: %q", logs.String())
	}
}

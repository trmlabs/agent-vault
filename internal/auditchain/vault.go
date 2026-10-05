package auditchain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// Logical is the subset of the Vault client the chain uses. The broker
// supplies its own authenticated client; *vaultapi.Logical satisfies it.
type Logical interface {
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vaultapi.Secret, error)
	WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error)
}

// KVKeys reads the HMAC key from a KV version 2 secret. Each KV version is a
// key version; writing a new version rotates the key. Field holds the key as
// standard base64 of at least 32 random bytes.
type KVKeys struct {
	Vault Logical
	Mount string
	Path  string
	Field string
}

func (k KVKeys) Current(ctx context.Context) (Key, error) { return k.read(ctx, 0) }

// Version reads one historical key version, for the verifier.
func (k KVKeys) Version(ctx context.Context, version int) ([]byte, error) {
	if version < 1 {
		return nil, errors.New("invalid audit key version")
	}
	key, err := k.read(ctx, version)
	if err != nil {
		return nil, err
	}
	return key.secret, nil
}

// read never includes Vault's response or the key in an error.
func (k KVKeys) read(ctx context.Context, version int) (Key, error) {
	if k.Vault == nil || !vaultPath(k.Mount) || !vaultPath(k.Path) || k.Field == "" {
		return Key{}, errors.New("audit key location is not configured")
	}
	var query map[string][]string
	if version > 0 {
		query = map[string][]string{"version": {strconv.Itoa(version)}}
	}
	secret, err := k.Vault.ReadWithDataWithContext(ctx, k.Mount+"/data/"+k.Path, query)
	if err != nil || secret == nil || secret.Data == nil {
		return Key{}, errors.New("audit key read failed")
	}
	data, _ := secret.Data["data"].(map[string]interface{})
	metadata, _ := secret.Data["metadata"].(map[string]interface{})
	encoded, _ := data[k.Field].(string)
	got, err := jsonInt(metadata["version"])
	if err != nil || encoded == "" || (version > 0 && got != version) {
		return Key{}, errors.New("audit key response incomplete")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Key{}, errors.New("audit key is not base64")
	}
	return NewKey(got, raw)
}

// TransitSigner signs checkpoints with an ed25519 Transit key, which never
// leaves Vault.
type TransitSigner struct {
	Vault Logical
	Mount string
	Key   string
}

func (t TransitSigner) Sign(ctx context.Context, input []byte) (string, error) {
	if t.Vault == nil || !vaultPath(t.Mount) || !vaultPath(t.Key) {
		return "", errors.New("audit signer is not configured")
	}
	secret, err := t.Vault.WriteWithContext(ctx, t.Mount+"/sign/"+t.Key, map[string]interface{}{"input": base64.StdEncoding.EncodeToString(input)})
	if err != nil || secret == nil {
		return "", errors.New("audit checkpoint signing failed")
	}
	signature, _ := secret.Data["signature"].(string)
	if _, _, ok := parseTransitSignature(signature); !ok {
		return "", errors.New("audit checkpoint signature malformed")
	}
	return signature, nil
}

// PublicKeys reads every version's public key for offline verification.
func (t TransitSigner) PublicKeys(ctx context.Context) (map[int]ed25519.PublicKey, error) {
	if t.Vault == nil || !vaultPath(t.Mount) || !vaultPath(t.Key) {
		return nil, errors.New("audit signer is not configured")
	}
	secret, err := t.Vault.ReadWithDataWithContext(ctx, t.Mount+"/keys/"+t.Key, nil)
	if err != nil || secret == nil {
		return nil, errors.New("audit public key read failed")
	}
	if kind, _ := secret.Data["type"].(string); kind != "ed25519" {
		return nil, errors.New("audit signing key must be ed25519")
	}
	versions, _ := secret.Data["keys"].(map[string]interface{})
	out := map[int]ed25519.PublicKey{}
	for name, value := range versions {
		version, err := strconv.Atoi(name)
		entry, _ := value.(map[string]interface{})
		encoded, _ := entry["public_key"].(string)
		raw, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if err != nil || decodeErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("audit public key version %q malformed", name)
		}
		out[version] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return nil, errors.New("audit public key response empty")
	}
	return out, nil
}

func jsonInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case float64:
		return int(n), nil
	default:
		return 0, errors.New("not a number")
	}
}

func vaultPath(p string) bool {
	if p == "" || len(p) > 256 {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if !pathRune(r) {
				return false
			}
		}
	}
	return true
}

func pathRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
}

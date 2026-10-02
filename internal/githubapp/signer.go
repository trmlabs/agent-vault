package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// Logical is the Vault client surface the signers use; *vaultapi.Logical has it.
type Logical interface {
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vaultapi.Secret, error)
	WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error)
}

// TransitSigner signs with an RSA key imported into Vault Transit, so the App
// private key never leaves Vault. The broker's policy needs only update on
// <mount>/sign/<key>/sha2-256.
type TransitSigner struct {
	Vault Logical
	Mount string
	Key   string
}

func (t TransitSigner) SignRS256(ctx context.Context, input []byte) ([]byte, error) {
	if t.Vault == nil || t.Mount == "" || t.Key == "" || strings.ContainsAny(t.Mount+t.Key, "?#% ") {
		return nil, ErrUnavailable
	}
	resp, err := t.Vault.WriteWithContext(ctx, t.Mount+"/sign/"+t.Key+"/sha2-256", map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input), "signature_algorithm": "pkcs1v15"})
	if err != nil || resp == nil {
		return nil, ErrUnavailable
	}
	signature, _ := resp.Data["signature"].(string)
	parts := strings.Split(signature, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, ErrUnavailable
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) < 256 {
		return nil, ErrUnavailable
	}
	return raw, nil
}

// KVSigner is the fallback: it reads the App private key (PEM) from a KV
// version 2 secret into broker memory for each signature. Prefer TransitSigner.
type KVSigner struct {
	Vault Logical
	Mount string
	Path  string
	Field string
}

func (k KVSigner) SignRS256(ctx context.Context, input []byte) ([]byte, error) {
	if k.Vault == nil {
		return nil, ErrUnavailable
	}
	resp, err := k.Vault.ReadWithDataWithContext(ctx, k.Mount+"/data/"+k.Path, nil)
	if err != nil || resp == nil || resp.Data == nil {
		return nil, ErrUnavailable
	}
	data, _ := resp.Data["data"].(map[string]interface{})
	encoded, _ := data[k.Field].(string)
	key, err := parseRSAKey(encoded)
	if err != nil {
		return nil, ErrUnavailable
	}
	digest := sha256.Sum256(input)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
}

func parseRSAKey(encoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return key, nil
}

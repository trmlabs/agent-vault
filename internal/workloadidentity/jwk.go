package workloadidentity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// publicMembers are the JWK members a pinned public key may carry. Anything
// else, and above all a private member (d, p, q, dp, dq, qi, k, oth), refuses
// the whole set: a pinned set is public keys and nothing more.
var publicMembers = map[string]bool{"kty": true, "kid": true, "alg": true, "use": true, "n": true, "e": true, "crv": true, "x": true, "y": true}

// parseJWK turns one public JWK into a verification key: RSA (RS256, at least
// 2048 bits) or EC P-256 (ES256). It reports ok false for anything else.
func parseJWK(m map[string]any) (kid string, key crypto.PublicKey, ok bool) {
	field := func(name string) string { s, _ := m[name].(string); return s }
	kid = field("kid")
	if kid == "" || (field("use") != "" && field("use") != "sig") {
		return "", nil, false
	}
	decode := func(name string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(field(name))
		if err != nil {
			return nil
		}
		return b
	}
	switch field("kty") {
	case "RSA":
		n, e := decode("n"), decode("e")
		if (field("alg") != "" && field("alg") != "RS256") || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return "", nil, false
		}
		exponent := int(new(big.Int).SetBytes(e).Int64())
		if exponent < 3 || exponent%2 == 0 {
			return "", nil, false
		}
		return kid, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, true
	case "EC":
		x, y := decode("x"), decode("y")
		if field("crv") != "P-256" || (field("alg") != "" && field("alg") != "ES256") || len(x) != 32 || len(y) != 32 {
			return "", nil, false
		}
		// The parser refuses a point not on the curve.
		encoded := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
		if err != nil {
			return "", nil, false
		}
		return kid, pub, true
	}
	return "", nil, false
}

// parsePinnedJWKS validates a pinned public key set strictly: 1 to 16 keys,
// each a valid public RSA or EC P-256 key with a unique kid, no private or
// unknown members. Any fault refuses the whole set.
func parsePinnedJWKS(raw json.RawMessage) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 64<<10 || d.Decode(&set) != nil {
		return nil, errors.New("pinned jwks must be a JSON key set")
	}
	if len(set.Keys) == 0 || len(set.Keys) > 16 {
		return nil, errors.New("pinned jwks needs 1 to 16 keys")
	}
	keys := map[string]crypto.PublicKey{}
	for _, m := range set.Keys {
		for member := range m {
			if !publicMembers[member] {
				return nil, errors.New("pinned jwks holds a private or unknown key member")
			}
		}
		kid, key, ok := parseJWK(m)
		if !ok || keys[kid] != nil {
			return nil, errors.New("pinned jwks key is not a valid public RSA or EC P-256 key with a unique kid")
		}
		keys[kid] = key
	}
	return keys, nil
}

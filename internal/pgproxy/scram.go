package pgproxy

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/text/secure/precis"
)

// scramClient drives the client side of a SASL SCRAM-SHA-256 exchange
// (RFC 5802 / RFC 7677) as PostgreSQL speaks it. The proxy authenticates to the
// upstream database with a Vault-issued username/password using this mechanism.
//
// Channel binding is not implemented (gs2 header "n,,"). Use verify-full for
// authenticated upstream TLS; this client does not support SCRAM-SHA-256-PLUS.
type scramClient struct {
	password    string
	clientNonce string

	// carried between messages
	firstBare       string
	authMessage     string
	serverSignature []byte
}

// scramMechanism is the only SASL mechanism the proxy offers upstream.
const scramMechanism = "SCRAM-SHA-256"

// newSCRAMClient builds a client for the given password with a fresh random
// client nonce. The nonce is 18 random bytes, base64-encoded — comfortably
// above the RFC-recommended minimum and matching libpq's sizing.
func newSCRAMClient(password string) (*scramClient, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("scram: generate nonce: %w", err)
	}
	// Match PostgreSQL: normalize valid SCRAM passwords, otherwise use raw bytes.
	if normalized, err := precis.OpaqueString.String(password); err == nil {
		password = normalized
	}
	return &scramClient{password: password, clientNonce: base64.StdEncoding.EncodeToString(raw)}, nil
}

// firstMessage returns the SCRAM client-first message
// ("n,,n=,r=<clientNonce>"). PostgreSQL derives the username from the startup
// packet and ignores the SCRAM "n=" field, so it is sent empty, as libpq does.
func (s *scramClient) firstMessage() string {
	s.firstBare = "n=,r=" + s.clientNonce
	return "n,," + s.firstBare
}

// finalMessage consumes the server-first message and returns the client-final
// message carrying the client proof. It also computes the server signature the
// caller later verifies via checkServerFinal.
func (s *scramClient) finalMessage(serverFirst string) (string, error) {
	combinedNonce, salt, iterations, err := parseServerFirst(serverFirst)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(combinedNonce, s.clientNonce) || len(combinedNonce) <= len(s.clientNonce) {
		return "", fmt.Errorf("scram: server nonce does not extend client nonce")
	}

	// gs2-header "n,," base64-encodes to "biws"; it is echoed in the channel-
	// binding field of the client-final message.
	finalWithoutProof := "c=biws,r=" + combinedNonce

	saltedPassword, err := pbkdf2.Key(sha256.New, s.password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("scram: derive salted password: %w", err)
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	s.authMessage = s.firstBare + "," + serverFirst + "," + finalWithoutProof
	clientSignature := hmacSHA256(storedKey[:], []byte(s.authMessage))

	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	s.serverSignature = hmacSHA256(serverKey, []byte(s.authMessage))

	return finalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof), nil
}

// checkServerFinal verifies the server's proof of the shared secret from the
// server-final message ("v=<ServerSignature>"). A mismatch means the upstream
// does not hold the expected password and the session must be aborted.
func (s *scramClient) checkServerFinal(serverFinal string) error {
	for _, part := range strings.Split(serverFinal, ",") {
		if strings.HasPrefix(part, "v=") {
			got, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return fmt.Errorf("scram: decode server signature: %w", err)
			}
			if subtle.ConstantTimeCompare(got, s.serverSignature) != 1 {
				return fmt.Errorf("scram: server signature mismatch")
			}
			return nil
		}
		if strings.HasPrefix(part, "e=") {
			return fmt.Errorf("scram: server error: %s", part[2:])
		}
	}
	return fmt.Errorf("scram: server-final message missing verifier")
}

func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// parseServerFirst extracts the combined nonce (r), salt (s), and iteration
// count (i) from a SCRAM server-first message.
func parseServerFirst(msg string) (nonce string, salt []byte, iterations int, err error) {
	var haveNonce, haveSalt, haveIter bool
	for _, part := range strings.Split(msg, ",") {
		switch {
		case strings.HasPrefix(part, "m="):
			return "", nil, 0, fmt.Errorf("scram: unsupported mandatory extension")
		case strings.HasPrefix(part, "r="):
			if haveNonce {
				return "", nil, 0, fmt.Errorf("scram: duplicate nonce")
			}
			nonce, haveNonce = part[2:], true
		case strings.HasPrefix(part, "s="):
			if haveSalt {
				return "", nil, 0, fmt.Errorf("scram: duplicate salt")
			}
			salt, err = base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return "", nil, 0, fmt.Errorf("scram: decode salt: %w", err)
			}
			haveSalt = true
		case strings.HasPrefix(part, "i="):
			if haveIter {
				return "", nil, 0, fmt.Errorf("scram: duplicate iterations")
			}
			iterations, err = strconv.Atoi(part[2:])
			if err != nil {
				return "", nil, 0, fmt.Errorf("scram: parse iteration count: %w", err)
			}
			haveIter = true
		}
	}
	if !haveNonce || !haveSalt || !haveIter {
		return "", nil, 0, fmt.Errorf("scram: malformed server-first message")
	}
	// Bound CPU work from an untrusted upstream; socket deadlines cannot
	// interrupt PBKDF2. PostgreSQL's default is 4096 iterations.
	if iterations < 1 || iterations > 1_000_000 {
		return "", nil, 0, fmt.Errorf("scram: iteration count outside supported range")
	}
	if len(salt) == 0 || len(salt) > 1024 {
		return "", nil, 0, fmt.Errorf("scram: invalid salt length")
	}
	return nonce, salt, iterations, nil
}

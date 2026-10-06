package brokercore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
)

// Identity kinds a verified scope carries, so each listener can admit only
// the kinds it was opened for.
const (
	// KindPodToken: a Pod's own projected token, checked against the live Pod
	// and the connection's source address.
	KindPodToken = "pod-token"
	// KindTokenReview: a projected token checked by online TokenReview.
	KindTokenReview = "token-review"
	// KindProxyAttested: a shared proxy's token and its attestation of the
	// agent Pod behind the connection.
	KindProxyAttested = "proxy-attested"
)

// defaultKinds are what an untagged listener admits: every kind except a
// proxy's attestation, which only a listener opened for it admits. The empty
// kind is a legacy session token.
var defaultKinds = []string{"", KindPodToken, KindTokenReview}

// KindedConn is a connection from a listener that admits only Kinds.
// Prefix, when set, is read before the connection: bytes a dispatcher
// already consumed to route it.
type KindedConn struct {
	net.Conn
	Kinds  []string
	Prefix io.Reader
}

func (c *KindedConn) Read(b []byte) (int, error) {
	if c.Prefix != nil {
		n, err := c.Prefix.Read(b)
		if n > 0 || err != io.EOF {
			return n, err
		}
		c.Prefix = nil
	}
	return c.Conn.Read(b)
}

// ConnKinds returns the identity kinds the connection's listener admits.
func ConnKinds(c net.Conn) []string {
	if k, ok := c.(*KindedConn); ok {
		return k.Kinds
	}
	return defaultKinds
}

// KindAdmitted reports whether a scope of this kind may use the listener.
func KindAdmitted(kinds []string, kind string) bool { return slices.Contains(kinds, kind) }

// deniedError is an identity refusal with a fixed reason code. It is
// ErrInvalidSession to every caller; the reason only reaches the broker's own
// log, so an operator can tell which check refused a workload. A refusal at
// the token's signing key also names the key ID the token claimed and the
// connection's peer, so a forged or stale token can be traced to its sender.
type deniedError struct {
	reason string
	key    *KeyDenial
}

// KeyDenial is what a signing-key refusal records: the token's key ID in a
// safe form and the connection's peer address. Never any part of the token.
type KeyDenial struct {
	// Kid is the token's key ID, or "invalid" when it is not a plain
	// identifier; KidSHA256 is then the first 12 hex characters of the
	// SHA-256 of the raw value. The kid is chosen by whoever made the token,
	// before any signature check, so it is never recorded raw.
	Kid       string
	KidSHA256 string
	Peer      string
}

var plainKid = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (e deniedError) Error() string {
	s := "workload not admitted: " + e.reason
	if k := e.key; k != nil {
		s += " kid=" + k.Kid
		if k.KidSHA256 != "" {
			s += " kid_sha256=" + k.KidSHA256
		}
		if k.Peer != "" {
			s += " peer=" + k.Peer
		}
	}
	return s
}

func (e deniedError) Is(target error) bool { return target == ErrInvalidSession }

// Denied returns ErrInvalidSession carrying a fixed reason code.
func Denied(reason string) error { return deniedError{reason: reason} }

// DeniedKey is Denied for a refusal at the token's signing key, naming the
// key ID the token claimed in its safe form.
func DeniedKey(reason, kid string) error {
	k := &KeyDenial{Kid: kid}
	if !plainKid.MatchString(kid) {
		sum := sha256.Sum256([]byte(kid))
		k.Kid, k.KidSHA256 = "invalid", hex.EncodeToString(sum[:])[:12]
	}
	return deniedError{reason: reason, key: k}
}

// WithPeer adds the connection's peer address to a signing-key refusal; any
// other error is returned unchanged.
func WithPeer(err error, peer netip.Addr) error {
	var d deniedError
	if !errors.As(err, &d) || d.key == nil || !peer.IsValid() {
		return err
	}
	k := *d.key
	k.Peer = peer.Unmap().String()
	return deniedError{reason: d.reason, key: &k}
}

// DenialKey returns a signing-key refusal's key ID and peer, or nil.
func DenialKey(err error) *KeyDenial {
	var d deniedError
	if errors.As(err, &d) && d.key != nil {
		k := *d.key
		return &k
	}
	return nil
}

// DenialReason returns the reason code of a refusal, or "".
func DenialReason(err error) string {
	var d deniedError
	if errors.As(err, &d) {
		return d.reason
	}
	return ""
}

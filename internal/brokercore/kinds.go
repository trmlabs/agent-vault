package brokercore

import (
	"io"
	"net"
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

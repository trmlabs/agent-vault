package pgproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
)

// sessionPreamble opens the line an in-Pod sidecar sends, inside its TLS
// stream and before the PostgreSQL startup it authors, to carry the Claude
// runner session token: "GHSESS1 <token>\n". It is never part of the client's
// startup packet, and it is eight bytes, the length of every startup frame's
// fixed header, so a stream without it is read unchanged.
const sessionPreamble = "GHSESS1 "

// attestationPreamble opens the line a shared proxy sends first, carrying its
// attestation of the agent Pod: "GHATTS1 <attestation>\n". It is also eight
// bytes, and the Attestor accepts it from a proxy binding alone.
const attestationPreamble = "GHATTS1 "

// maxSessionBytes bounds each preamble line before authentication. The
// caller's startup deadline bounds how long it may take to arrive.
const maxSessionBytes = 8 * 1024

var errSessionPreamble = errors.New("malformed session preamble")

// readSessionPreamble returns the relayed session token and attestation
// (each empty when none) and a reader that yields the rest of the stream,
// including any bytes read while looking for a preamble. An attestation line,
// when present, comes first. It reads only what it consumes from conn.
func readSessionPreamble(conn net.Conn) (string, string, io.Reader, error) {
	head := make([]byte, len(sessionPreamble))
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", "", nil, err
	}
	attestation := ""
	if string(head) == attestationPreamble {
		line, err := readPreambleLine(conn)
		if err != nil {
			return "", "", nil, err
		}
		attestation = line
		if _, err := io.ReadFull(conn, head); err != nil {
			return "", "", nil, err
		}
	}
	if string(head) != sessionPreamble {
		return "", attestation, io.MultiReader(bytes.NewReader(head), conn), nil
	}
	session, err := readPreambleLine(conn)
	if err != nil {
		return "", "", nil, err
	}
	return session, attestation, conn, nil
}

// readPreambleLine reads one non-empty base64url line up to its newline.
func readPreambleLine(conn net.Conn) (string, error) {
	var token []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			break
		}
		// A JWT or attestation is base64url and dots; anything else is not.
		if len(token) >= maxSessionBytes || !tokenByte(one[0]) {
			return "", errSessionPreamble
		}
		token = append(token, one[0])
	}
	if len(token) == 0 {
		return "", errSessionPreamble
	}
	// The string copy lives for the session, because every recheck verifies it
	// again; the read buffer does not.
	line := string(token)
	clear(token)
	return line, nil
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

type sessionKey struct{}

// WithSession carries a connection's relayed runner session token to the
// DatabaseResolver, which verifies it on admission and at every recheck.
func WithSession(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionKey{}, token)
}

// Session returns the relayed runner session token, or "".
func Session(ctx context.Context) string {
	token, _ := ctx.Value(sessionKey{}).(string)
	return token
}

// Requester is who stands behind a connection and the decision on its
// database, as the resolver established it for the audit trail. It holds no
// credential: the token is identified only by its hash.
type Requester struct {
	Kind, Subject, ObjectID, TokenSHA256 string
	Tier, Decision, Groups               string
	CacheAgeSec                          int64
}

type requesterKey struct{}

func withRequesterRecord(ctx context.Context, r *Requester) context.Context {
	return context.WithValue(ctx, requesterKey{}, r)
}

// RecordRequester lets a resolver report the requester and decision for the
// connection's audit event. Outside an admission it does nothing.
func RecordRequester(ctx context.Context, r Requester) {
	if rec, ok := ctx.Value(requesterKey{}).(*Requester); ok && rec != nil {
		*rec = r
	}
}

// RefusedError is a resolver's authorization refusal: the database exists and
// the pool is granted it, but this requester may not use it. Outcome is the
// audit decision code.
type RefusedError struct{ Outcome string }

func (e *RefusedError) Error() string { return "not authorized: " + e.Outcome }

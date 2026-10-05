package pgproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

// maxReadOnlyStatementBytes bounds a Query or Parse message the read-only
// relay holds to classify, as the pooled path bounds every message.
const maxReadOnlyStatementBytes = 64 << 20

// relayReadOnly is relay for a read-only login on the unpooled path. The
// client's messages are read whole and its statements classified, so one that
// could create a temporary object never reaches the database. The upstream
// direction stays a byte copy that only tracks message boundaries.
//
// refused reports a refused statement. The session then ends: the database
// stream is stopped first, and clean reports whether it stopped between
// messages, so the caller can still send the client a refusal it can read.
func relayReadOnly(client, upstream net.Conn) (refused, clean bool) {
	toClient := &frameTracker{w: client}
	fromClient := make(chan bool, 1)
	fromServer := make(chan struct{})
	go func() { fromClient <- copyClientReadOnly(upstream, client) }()
	go func() {
		defer close(fromServer)
		_, _ = io.Copy(toClient, upstream)
	}()
	select {
	case refused = <-fromClient:
		_ = upstream.Close()
		<-fromServer
		if !refused {
			_ = client.Close()
		}
		return refused, refused && toClient.atBoundary()
	case <-fromServer:
		_ = client.Close()
		_ = upstream.Close()
		<-fromClient
		return false, false
	}
}

// copyClientReadOnly forwards client messages to upstream until the client
// leaves, a write fails, or a statement is refused (true). A fast-path
// FunctionCall names its function by OID, so it is refused too.
func copyClientReadOnly(upstream io.Writer, client io.Reader) bool {
	r := bufio.NewReaderSize(client, 32<<10)
	w := bufio.NewWriterSize(upstream, 32<<10)
	var header [5]byte
	started := false
	for {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return false
		}
		length := int64(binary.BigEndian.Uint32(header[1:]))
		if length < 4 {
			return false // malformed: end the session
		}
		body := length - 4
		switch header[0] {
		case 'F':
			return true
		case 'Q', 'P':
			if body > maxReadOnlyStatementBytes {
				return true // too large to classify: fail closed
			}
			payload := make([]byte, body)
			if _, err := io.ReadFull(r, payload); err != nil {
				return false
			}
			sql, ok := statementText(header[0], payload)
			if !ok {
				return false // malformed: end the session
			}
			refused := false
			if refused, started = changesLexer(sql, started); refused || !readOnlyAllowed(sql) {
				return true
			}
			if _, err := w.Write(header[:]); err != nil {
				return false
			}
			if _, err := w.Write(payload); err != nil {
				return false
			}
		default:
			if _, err := w.Write(header[:]); err != nil {
				return false
			}
			if _, err := io.CopyN(w, r, body); err != nil {
				return false
			}
		}
		// Flush once the client has nothing more buffered, so a pipelined
		// batch goes upstream together and a lone message without delay.
		if r.Buffered() == 0 {
			if err := w.Flush(); err != nil {
				return false
			}
		}
	}
}

// statementText returns the SQL of a Query ('Q') or Parse ('P') message body.
func statementText(kind byte, payload []byte) (string, bool) {
	if kind == 'P' {
		name := bytes.IndexByte(payload, 0)
		if name < 0 {
			return "", false
		}
		payload = payload[name+1:]
	}
	end := bytes.IndexByte(payload, 0)
	if end < 0 {
		return "", false
	}
	return string(payload[:end]), true
}

// frameTracker passes the server's byte stream to the client and follows its
// message framing, so the relay knows whether the stream stopped between two
// messages.
type frameTracker struct {
	w         io.Writer
	header    [5]byte
	have      int   // header bytes seen of the current message
	remaining int64 // body bytes still to come
	broken    bool
}

func (t *frameTracker) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	t.advance(p[:n])
	return n, err
}

func (t *frameTracker) advance(p []byte) {
	for len(p) > 0 && !t.broken {
		if t.remaining > 0 {
			k := int64(len(p))
			if k > t.remaining {
				k = t.remaining
			}
			t.remaining -= k
			p = p[k:]
			continue
		}
		k := copy(t.header[t.have:], p)
		t.have += k
		p = p[k:]
		if t.have == len(t.header) {
			t.have = 0
			length := int64(binary.BigEndian.Uint32(t.header[1:]))
			if length < 4 {
				t.broken = true
				return
			}
			t.remaining = length - 4
		}
	}
}

func (t *frameTracker) atBoundary() bool { return !t.broken && t.have == 0 && t.remaining == 0 }

package pgproxy

import (
	"encoding/binary"
	"fmt"
	"io"
)

// messageReader prevents pgproto3's chunk reader from consuming bytes from the
// next wire message. After ReadyForQuery/PasswordMessage, the connection can be
// handed to the raw relay without losing pipelined queries or notifications.
// It buffers only a header, never an attacker-controlled body length.
type messageReader struct {
	reader    io.Reader
	startup   bool
	header    [5]byte
	buffered  []byte
	remaining int
}

func (r *messageReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buffered) == 0 && r.remaining == 0 {
		size := 5
		if r.startup {
			size = 4
		}
		if _, err := io.ReadFull(r.reader, r.header[:size]); err != nil {
			return 0, err
		}
		length := int(int32(binary.BigEndian.Uint32(r.header[size-4 : size])))
		if length < 4 {
			return 0, fmt.Errorf("invalid PostgreSQL frame length")
		}
		r.remaining = length - 4
		r.buffered = r.header[:size]
	}
	if len(r.buffered) > 0 {
		n := copy(p, r.buffered)
		r.buffered = r.buffered[n:]
		return n, nil
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= n
	return n, err
}

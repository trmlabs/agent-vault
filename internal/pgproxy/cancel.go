package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
)

type cancelRequestError struct{ request *pgproto3.CancelRequest }

func (*cancelRequestError) Error() string { return errCancelRequest.Error() }
func (*cancelRequestError) Unwrap() error { return errCancelRequest }

// The client receives a fresh opaque capability, never the upstream cancel
// secret. Entries exist only while their session is alive. Per-target locking
// bounds cancel connections and keeps teardown from racing an in-flight cancel.
type cancelTarget struct {
	mu     sync.Mutex
	active bool
	addr   string
	svc    DatabaseService
	key    pgproto3.CancelRequest
}

func cancelKey(pid uint32, secret []byte) string {
	return string(binary.BigEndian.AppendUint32(nil, pid)) + string(secret)
}

func (b *Broker) registerCancel(sess *upstreamSession, svc *DatabaseService) (func(), error) {
	if sess.backendKey == nil {
		return func() {}, nil
	}
	target := &cancelTarget{active: true, addr: sess.conn.RemoteAddr().String(), svc: *svc,
		key: pgproto3.CancelRequest{ProcessID: sess.backendKey.ProcessID, SecretKey: append([]byte(nil), sess.backendKey.SecretKey...)}}
	for {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, fmt.Errorf("generate cancellation capability: %w", err)
		}
		pid, secret := binary.BigEndian.Uint32(random[:4]), random[4:]
		key := cancelKey(pid, secret)
		b.mu.Lock()
		if _, exists := b.cancellations[key]; exists {
			b.mu.Unlock()
			continue
		}
		b.cancellations[key] = target
		b.mu.Unlock()
		sess.backendKey = &pgproto3.BackendKeyData{ProcessID: pid, SecretKey: append([]byte(nil), secret...)}
		return func() {
			b.mu.Lock()
			delete(b.cancellations, key)
			b.mu.Unlock()
			target.mu.Lock()
			target.active = false
			target.mu.Unlock()
		}, nil
	}
}

func (b *Broker) cancelQuery(ctx context.Context, request *pgproto3.CancelRequest) {
	b.mu.Lock()
	target := b.cancellations[cancelKey(request.ProcessID, request.SecretKey)]
	b.mu.Unlock()
	if target == nil || !target.mu.TryLock() {
		return
	}
	defer target.mu.Unlock()
	if !target.active {
		return
	}
	// Pin to the established backend's peer: resolving a load-balanced hostname
	// again could cancel a different server's coincidentally matching PID.
	conn, err := b.opts.Dialer(ctx, "tcp", target.addr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	secured, _, err := negotiateUpstreamTLS(ctx, conn, &target.svc)
	if err != nil {
		return
	}
	packet, err := target.key.Encode(nil)
	if err != nil {
		return
	}
	if _, err = secured.Write(packet); err != nil {
		return
	}
	// PostgreSQL closes the cancel connection after processing. Waiting avoids
	// reporting completion before it has received the cancellation packet.
	_, _ = io.Copy(io.Discard, secured)
}

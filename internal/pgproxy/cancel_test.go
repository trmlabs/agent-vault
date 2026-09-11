package pgproxy

import (
	"context"
	"github.com/jackc/pgx/v5/pgproto3"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancellationCapabilityIsIsolatedAndExpires(t *testing.T) {
	var dials atomic.Int32
	received := make(chan *pgproto3.CancelRequest, 2)
	b := New("", Options{Dialer: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			msg, err := pgproto3.NewBackend(server, io.Discard).ReceiveStartupMessage()
			if err == nil {
				if req, ok := msg.(*pgproto3.CancelRequest); ok {
					received <- req
				}
			}
		}()
		return client, nil
	}})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	sess := &upstreamSession{conn: client, backendKey: &pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}}
	unregister, err := b.registerCancel(sess, &DatabaseService{Addr: "db:5432", SSLMode: "disable"})
	if err != nil {
		t.Fatal(err)
	}
	key := sess.backendKey
	if key.ProcessID == 42 && string(key.SecretKey) == string([]byte{1, 2, 3, 4}) {
		t.Fatal("upstream capability leaked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b.cancelQuery(ctx, &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: []byte{0, 0, 0, 0}})
	if dials.Load() != 0 {
		t.Fatal("forged capability opened upstream")
	}
	request := &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey}
	b.cancelQuery(ctx, request)
	select {
	case got := <-received:
		if got.ProcessID != 42 || string(got.SecretKey) != string([]byte{1, 2, 3, 4}) {
			t.Fatal("cancel reached wrong backend")
		}
	default:
		t.Fatal("valid cancel not delivered")
	}
	unregister()
	b.cancelQuery(ctx, request)
	if dials.Load() != 1 {
		t.Fatal("expired capability opened upstream")
	}
	if len(b.cancellations) != 0 {
		t.Fatal("cancellation map leaked session")
	}
}

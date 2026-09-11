package pgproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestBroker_RejectsNonLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- verifies wildcard listeners are rejected and closed without accepting.
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	b := New(ln.Addr().String(), Options{})
	if err := b.Serve(ln); err == nil {
		t.Fatal("plaintext listener accepted remote connections")
	}
}

func TestBroker_PendingBudgetReleasedAfterAdmission(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	b, addr := startBroker(t, Options{MaxPendingConns: 1, MaxConns: 3, Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: newLease()}})
	first := openAgentSession(t, addr, "token", "db")
	defer first.close()
	second := openAgentSession(t, addr, "token", "db")
	defer second.close()
	if len(b.acceptSem) != 0 {
		t.Fatal("serving sessions hold pending slots")
	}
}

func TestBroker_PipelinedPasswordAndQuery(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	lease := newLease()
	_, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: &fakeMinter{lease: lease}})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "db"}})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.Receive(); err != nil {
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "token"})
	fe.Send(&pgproto3.Query{String: "SELECT current_user"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	ready := 0
	got := ""
	for ready < 2 {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("pipelined query lost: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ReadyForQuery:
			ready++
		case *pgproto3.DataRow:
			got = string(m.Values[0])
		case *pgproto3.ErrorResponse:
			t.Fatal(m.Message)
		}
	}
	if got != lease.Username {
		t.Fatalf("query did not reach upstream")
	}
}

func TestUpstream_PreservesMessageAfterReady(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		be := pgproto3.NewBackend(server, server)
		if _, err := be.ReceiveStartupMessage(); err != nil {
			done <- err
			return
		}
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		be.Send(&pgproto3.NoticeResponse{Message: "after-ready"})
		done <- be.Flush()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sess, err := connectUpstream(ctx, func(context.Context, string, string) (net.Conn, error) { return client, nil }, &DatabaseService{Addr: "unused:5432", SSLMode: "disable"}, newLease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.conn.SetReadDeadline(time.Now().Add(time.Second))
	msg, err := pgproto3.NewFrontend(sess.conn, io.Discard).Receive()
	if err != nil {
		t.Fatalf("trailing upstream message lost: %v", err)
	}
	notice, ok := msg.(*pgproto3.NoticeResponse)
	if !ok || notice.Message != "after-ready" {
		t.Fatalf("unexpected trailing message %T", msg)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type blockingMint struct {
	*fakeMinter
	started chan struct{}
}

func (m *blockingMint) Mint(ctx context.Context, _ string, _ *DatabaseService) (*Lease, error) {
	close(m.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestBroker_ShutdownCancelsMint(t *testing.T) {
	m := &blockingMint{fakeMinter: &fakeMinter{}, started: make(chan struct{})}
	b, addr := startBroker(t, Options{Auth: &fakeAuth{scope: &AgentScope{VaultID: "v", ActorID: "a"}}, Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: "unused:5432"}}, Leases: m})
	done := make(chan struct{})
	go func() { defer close(done); connectExpectCode(t, addr, "token", "db") }()
	select {
	case <-m.started:
	case <-time.After(time.Second):
		t.Fatal("mint did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed to cancel mint: %v", err)
	}
	<-done
	if len(b.serveSem) != 0 || len(b.acceptSem) != 0 {
		t.Fatal("shutdown leaked connection slots")
	}
	if err := b.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSCRAM_RejectsUnboundedWorkAndAmbiguousMessages(t *testing.T) {
	for _, first := range []string{"r=abcXYZ,s=c2FsdA==,i=1000001", "r=abc,s=c2FsdA==,i=4096", "r=abcXYZ,r=abcDEF,s=c2FsdA==,i=4096", "m=required,r=abcXYZ,s=c2FsdA==,i=4096"} {
		t.Run(first, func(t *testing.T) {
			c := &scramClient{password: "pencil", clientNonce: "abc"}
			c.firstMessage()
			if _, err := c.finalMessage(first); err == nil {
				t.Fatal("accepted invalid SCRAM challenge")
			}
		})
	}
}

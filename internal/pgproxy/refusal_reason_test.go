package pgproxy

import (
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// refusalReason opens a session and returns the reason the broker gave.
func refusalReason(t *testing.T, addr, header string) (code, reason string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(header))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "appdb"}})
	_ = fe.Flush()
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("no refusal: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: "projected-token"})
			_ = fe.Flush()
		case *pgproto3.ErrorResponse:
			return m.Code, m.UnknownFields[brokercore.RefusalReasonField]
		case *pgproto3.ReadyForQuery:
			t.Fatal("admitted")
		}
	}
}

// The broker names each refusal with a reason code a relay can map, so the
// per-worker cap and a full database budget, both 53300, stay distinct.
func TestBrokerRefusalsCarryAReason(t *testing.T) {
	addr := poolBroker(t, &fakePeerAuth{}, 1)
	held, err := openSession(t, addr, header("10.244.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if code, reason := refusalReason(t, addr, header("10.244.0.9")); code != "53300" || reason != "actor_limit" {
		t.Fatalf("worker cap refusal %s/%q", code, reason)
	}
	r := &sessionResolver{}
	r.want.Store("another")
	addr = sessionBroker(t, r)
	if code, reason := refusalReason(t, addr, header("10.244.0.9")+"GHSESS1 "+runnerToken+"\n"); code != "42501" || reason != "not_entitled" {
		t.Fatalf("authorization refusal %s/%q", code, reason)
	}
}

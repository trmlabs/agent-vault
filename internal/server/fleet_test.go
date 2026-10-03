package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

type sessionStore struct{ err error }

func (s sessionStore) AddBrokerSession(context.Context, string, string, string, int) error {
	return s.err
}
func (s sessionStore) RemoveBrokerSession(context.Context, string) error { return nil }

func TestSessionLedgerMapsTheStoreLimit(t *testing.T) {
	ledger := sessionLedger{store: sessionStore{err: store.ErrPodSessionLimit}, owner: func() string { return "owner" }}
	if err := ledger.Add(context.Background(), "s", "pod", 1); !errors.Is(err, pgproxy.ErrSessionLimit) {
		t.Fatalf("err %v", err)
	}
	down := sessionLedger{store: sessionStore{err: errors.New("down")}, owner: func() string { return "owner" }}
	if err := down.Add(context.Background(), "s", "pod", 1); err == nil || errors.Is(err, pgproxy.ErrSessionLimit) {
		t.Fatalf("store outage must refuse, not look like a cap: %v", err)
	}
	if NewSessionLedger(struct{}{}, nil) != nil {
		t.Fatal("a store without sessions produced a ledger")
	}
}

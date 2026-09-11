package pgproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type authFunc func(context.Context, string, string) (*AgentScope, error)

func (f authFunc) Authenticate(ctx context.Context, token, hint string) (*AgentScope, error) {
	return f(ctx, token, hint)
}

type resolverFunc func(context.Context, AgentScope, string) (*DatabaseService, error)

func (f resolverFunc) ResolveDatabase(ctx context.Context, scope AgentScope, requested string) (*DatabaseService, error) {
	return f(ctx, scope, requested)
}

func TestAuthorizationRevocationClosesAndRevokesSession(t *testing.T) {
	up := startFakeUpstream(t, authTrust, "")
	var revoked atomic.Bool
	scope := &AgentScope{VaultID: "v", ActorID: "a"}
	minter := &fakeMinter{lease: newLease()}
	b, addr := startBroker(t, Options{AuthorizationInterval: 10 * time.Millisecond,
		Auth: authFunc(func(context.Context, string, string) (*AgentScope, error) {
			if revoked.Load() {
				return nil, errors.New("revoked")
			}
			return scope, nil
		}),
		Databases: &fakeResolver{svc: &DatabaseService{Name: "db", Addr: up.addr()}}, Leases: minter})
	client := openAgentSession(t, addr, "token", "db")
	defer client.close()
	revoked.Store(true)
	waitFor(t, time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "revoked identity retained a DB lease")
	waitFor(t, time.Second, func() bool { return len(b.serveSem) == 0 }, "session slot not released")
}

func TestAuthorizationRecheckFailuresAndCapacityChange(t *testing.T) {
	scope := AgentScope{VaultID: "v", ActorID: "a"}
	svc := DatabaseService{Name: "db", Addr: "host:5432", Role: "readonly"}
	for _, mode := range []string{"deleted", "role-change", "identity-change", "stall", "capacity-only"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var checks atomic.Int32
			terminated := make(chan struct{}, 1)
			b := New("", Options{AuthorizationInterval: time.Millisecond, AuthorizationTimeout: 20 * time.Millisecond,
				Auth: authFunc(func(ctx context.Context, _, _ string) (*AgentScope, error) {
					if mode == "stall" {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					copy := scope
					if mode == "identity-change" {
						copy.ActorID = "other"
					}
					return &copy, nil
				}),
				Databases: resolverFunc(func(context.Context, AgentScope, string) (*DatabaseService, error) {
					checks.Add(1)
					copy := svc
					switch mode {
					case "deleted":
						return nil, errors.New("deleted")
					case "role-change":
						copy.Role = "writer"
					case "capacity-only":
						copy.MaxConns = 1
					}
					return &copy, nil
				})})
			done := make(chan struct{})
			go func() {
				defer close(done)
				b.authorizationLoop(ctx, "token", "", "db", scope, svc, func() {
					select {
					case terminated <- struct{}{}:
					default:
					}
				})
			}()
			if mode == "capacity-only" {
				waitFor(t, time.Second, func() bool { return checks.Load() >= 3 }, "no authorization checks")
				select {
				case <-terminated:
					t.Fatal("capacity update terminated a valid session")
				default:
				}
				cancel()
			} else {
				select {
				case <-terminated:
				case <-time.After(time.Second):
					t.Fatal("authorization failure did not terminate session")
				}
			}
			cancel()
			<-done
		})
	}
}

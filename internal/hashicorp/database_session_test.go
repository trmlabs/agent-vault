package hashicorp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDatabaseSessionPolicyAndAccessorCustody(t *testing.T) {
	policy := DatabaseCredentialPolicyName("database", "reader")
	var minted, revoked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/create":
			body := decodeBody(t, r)
			policies := body["policies"].([]interface{})
			if len(policies) != 1 || policies[0] != policy || body["no_default_policy"] != true || body["renewable"] != false || body["type"] != "service" || body["ttl"] != "1m0s" || body["explicit_max_ttl"] != "1m0s" {
				t.Error("child token was not constrained")
			}
			writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "child-secret", "accessor": "cleanup-ref", "policies": []string{policy}, "lease_duration": 60, "renewable": false}})
		case "/v1/database/creds/reader":
			if r.Header.Get("X-Vault-Token") != "child-secret" {
				t.Error("issued under parent token")
			}
			minted.Add(1)
			writeJSON(w, map[string]any{"lease_id": "db/lease", "lease_duration": 30, "renewable": true, "data": map[string]any{"username": "user", "password": "synthetic-password"}})
		case "/v1/auth/token/revoke-accessor":
			if body := decodeBody(t, r); body["accessor"] != "cleanup-ref" {
				t.Error("wrong cleanup reference")
			}
			revoked.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected API path", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newClientForServer(t, srv.URL)
	session, err := c.NewDatabaseSession(context.Background(), "database", "reader", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if minted.Load() != 0 || session.Accessor != "cleanup-ref" {
		t.Fatal("credential issued before accessor was returned")
	}
	if _, err = session.ReadCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = c.RevokeDatabaseSession(context.Background(), session.Accessor); err != nil {
		t.Fatal(err)
	}
	if minted.Load() != 1 || revoked.Load() != 1 {
		t.Fatal("wrong lifecycle counts")
	}
}

func TestDatabaseSessionRejectsBroaderPolicy(t *testing.T) {
	var minted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-accessor" {
			w.WriteHeader(204)
			return
		}
		if strings.Contains(r.URL.Path, "/creds/") {
			minted.Store(true)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "child", "accessor": "ref", "policies": []string{"root"}, "lease_duration": 60}})
	}))
	defer srv.Close()
	c := newClientForServer(t, srv.URL)
	if _, err := c.NewDatabaseSession(context.Background(), "database", "reader", time.Minute); err == nil {
		t.Fatal("broader child policy accepted")
	}
	if minted.Load() {
		t.Fatal("database credential minted on rejected policy")
	}
}

func TestDatabaseSessionAccessorRetryOnlyAcceptsMissingAccessor(t *testing.T) {
	for _, test := range []struct {
		message string
		ok      bool
	}{{"invalid accessor", true}, {"permission denied", false}, {"database unavailable", false}} {
		t.Run(test.message, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{test.message}})
			}))
			defer srv.Close()
			err := newClientForServer(t, srv.URL).RevokeDatabaseSession(context.Background(), "ref")
			if (err == nil) != test.ok {
				t.Fatalf("cleanup result %v", err)
			}
		})
	}
}

func TestDatabaseProviderErrorsDoNotExposeResponseBody(t *testing.T) {
	const canary = "synthetic-provider-error-credential-canary"
	for _, phase := range []string{"create", "read", "child-read", "revoke-accessor", "revoke-lease", "confirm-lease", "renew", "legacy-revoke"} {
		t.Run(phase, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "confirm-lease" && strings.Contains(r.URL.Path, "/revoke/") {
					w.WriteHeader(204)
					return
				}
				w.WriteHeader(403)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{canary}})
			}))
			defer srv.Close()
			c := newClientForServer(t, srv.URL)
			ctx := context.Background()
			var err error
			switch phase {
			case "create":
				_, err = c.NewDatabaseSession(ctx, "database", "reader", time.Minute)
			case "read":
				_, err = c.ReadDatabaseCredential(ctx, "database", "reader")
			case "child-read":
				session := DatabaseSession{client: c, ExpiresAt: time.Now().Add(time.Minute), mount: "database", role: "reader"}
				_, err = session.ReadCredential(ctx)
			case "revoke-accessor":
				err = c.RevokeDatabaseSession(ctx, "ref")
			case "revoke-lease", "confirm-lease":
				err = c.RevokeDatabaseLeaseConfirmed(ctx, "database/creds/reader/lease")
			case "renew":
				_, err = c.RenewLease(ctx, "lease", time.Minute)
			case "legacy-revoke":
				err = c.RevokeLease(ctx, "lease")
			}
			if err == nil || strings.Contains(err.Error(), canary) {
				t.Fatalf("phase %s did not return a scrubbed failure", phase)
			}
		})
	}
}

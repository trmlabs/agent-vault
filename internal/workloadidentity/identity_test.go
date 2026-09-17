package workloadidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

type fakeStore struct {
	status, role string
	err          error
	onRole       func()
}

func (s *fakeStore) GetAgentByID(context.Context, string) (*store.Agent, error) {
	return &store.Agent{ID: "agent", Status: s.status}, s.err
}
func (s *fakeStore) GetVaultByID(context.Context, string) (*store.Vault, error) {
	return &store.Vault{ID: "vault", Name: "allowed"}, s.err
}
func (s *fakeStore) GetVaultRole(context.Context, string, string) (string, error) {
	if s.onRole != nil {
		s.onRole()
	}
	return s.role, s.err
}

type fixture struct {
	r                       *Resolver
	s                       *fakeStore
	c                       claims
	review                  review
	pod                     map[string]any
	reviewStatus, podStatus int
	malformed               bool
	delay                   time.Duration
	calls                   atomic.Int64
	reviewer                string
}

// This TLS HTTP fixture tests the wire contract and fail-closed behavior. It
// does not mint real Kubernetes tokens or establish deployed runtime evidence.
func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{s: &fakeStore{status: "active", role: "proxy"}, reviewStatus: 201, podStatus: 200, reviewer: "reviewer-canary"}
	f.c.Issuer, f.c.Subject, f.c.Audience = "https://issuer.test", "system:serviceaccount:work:runner", []string{"credential-proxy"}
	f.c.Issued = time.Now().Unix() - 1
	f.c.Expires = f.c.Issued + 600
	f.c.Kubernetes.Namespace = "work"
	f.c.Kubernetes.ServiceAccount.Name, f.c.Kubernetes.ServiceAccount.UID = "runner", "account-uid"
	f.c.Kubernetes.Pod.Name, f.c.Kubernetes.Pod.UID = "run", "pod-uid"
	f.review.APIVersion, f.review.Kind = "authentication.k8s.io/v1", "TokenReview"
	f.review.Status.Authenticated = true
	f.review.Status.Audiences = []string{"credential-proxy"}
	f.review.Status.User.Username, f.review.Status.User.UID = f.c.Subject, "account-uid"
	f.review.Status.User.Extra = map[string][]string{"authentication.kubernetes.io/pod-name": {"run"}, "authentication.kubernetes.io/pod-uid": {"pod-uid"}}
	f.pod = map[string]any{"metadata": map[string]any{"name": "run", "namespace": "work", "uid": "pod-uid"}, "spec": map[string]any{"serviceAccountName": "runner"}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+f.reviewer {
			w.WriteHeader(401)
			return
		}
		if f.delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(f.delay):
			}
		}
		if f.malformed {
			w.Write([]byte("{invalid"))
			return
		}
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			if r.Method != http.MethodPost {
				t.Error("wrong review method")
			}
			var got review
			if json.NewDecoder(r.Body).Decode(&got) != nil || got.Spec.Token != token(f.c) || !exactly(got.Spec.Audiences, "credential-proxy") {
				t.Error("invalid TokenReview request")
			}
			w.WriteHeader(f.reviewStatus)
			json.NewEncoder(w).Encode(f.review)
		case "/api/v1/namespaces/work/pods/run":
			if r.Method != http.MethodGet {
				t.Error("wrong pod method")
			}
			w.WriteHeader(f.podStatus)
			json.NewEncoder(w).Encode(f.pod)
		default:
			t.Error("unexpected API path")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "reviewer")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(f.reviewer), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{APIServer: srv.URL, CAFile: caFile, ReviewerTokenFile: tokenFile, Issuer: f.c.Issuer, Audience: "credential-proxy", Bindings: []Binding{{Namespace: "work", ServiceAccount: "runner", ServiceAccountUID: "account-uid", AgentID: "agent", VaultID: "vault"}}}
	var err error
	f.r, err = New(c, f.s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func token(c claims) string {
	b, _ := json.Marshal(c)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".fixture-signature"
}

func TestResolveLiveAuthorization(t *testing.T) {
	f := setup(t)
	for i := 0; i < 2; i++ {
		s, err := f.r.ResolveForProxy(context.Background(), token(f.c), "")
		if err != nil || s.AgentID != "agent" || s.WorkloadID != "pod-uid" || s.VaultID != "vault" || s.VaultName != "allowed" || s.VaultRole != "proxy" {
			t.Fatalf("unexpected scope or error: %+v %v", s, err)
		}
	}
	if f.calls.Load() != 4 {
		t.Fatal("every resolution must review token and current pod; proofs are deliberately replayable")
	}
	f.s.role = ""
	if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); !errors.Is(err, brokercore.ErrVaultAccessDenied) {
		t.Fatal("removed grant admitted")
	}
	f.s.role = "proxy"
	f.s.status = "revoked"
	if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); !errors.Is(err, brokercore.ErrInvalidSession) {
		t.Fatal("revoked identity admitted")
	}
}

func TestDenyProofAndVerifierFailures(t *testing.T) {
	cases := map[string]func(*fixture){
		"issuer":                func(f *fixture) { f.c.Issuer = "other" },
		"audience":              func(f *fixture) { f.c.Audience = []string{"other"} },
		"multiple-audiences":    func(f *fixture) { f.c.Audience = []string{"credential-proxy", "other-service"} },
		"duplicate-audience":    func(f *fixture) { f.c.Audience = []string{"credential-proxy", "credential-proxy"} },
		"review-extra-audience": func(f *fixture) { f.review.Status.Audiences = []string{"credential-proxy", "other-service"} },
		"expired":               func(f *fixture) { f.c.Expires = time.Now().Unix() - 1 },
		"future-issued":         func(f *fixture) { f.c.Issued = time.Now().Unix() + 60 },
		"not-yet-valid":         func(f *fixture) { f.c.NotBefore = time.Now().Unix() + 60 },
		"excess-lifetime":       func(f *fixture) { f.c.Expires = f.c.Issued + 3601 },
		"missing-expiry":        func(f *fixture) { f.c.Expires = 0 },
		"account":               func(f *fixture) { f.c.Kubernetes.ServiceAccount.Name = "other" },
		"recreated-account":     func(f *fixture) { f.c.Kubernetes.ServiceAccount.UID = "new" },
		"unbound":               func(f *fixture) { f.c.Kubernetes.Pod.UID = "" },
		"subject":               func(f *fixture) { f.c.Subject = "other" },
		"path-injection":        func(f *fixture) { f.c.Kubernetes.Pod.Name = "../other" },
		"wrong-pinned-pod":      func(f *fixture) { f.r.config.Bindings[0].PodUID = "other" },
		"unauthenticated":       func(f *fixture) { f.review.Status.Authenticated = false },
		"review-error":          func(f *fixture) { f.review.Status.Error = "token canary" },
		"review-audience":       func(f *fixture) { f.review.Status.Audiences = nil },
		"review-user":           func(f *fixture) { f.review.Status.User.Username = "other" },
		"review-uid":            func(f *fixture) { f.review.Status.User.UID = "other" },
		"review-pod-uid": func(f *fixture) {
			f.review.Status.User.Extra["authentication.kubernetes.io/pod-uid"] = []string{"other"}
		},
		"missing-pod-extra":    func(f *fixture) { f.review.Status.User.Extra = nil },
		"review-denied":        func(f *fixture) { f.reviewStatus = 403 },
		"review-outage":        func(f *fixture) { f.reviewStatus = 503 },
		"review-redirect":      func(f *fixture) { f.reviewStatus = 307 },
		"review-malformed":     func(f *fixture) { f.malformed = true },
		"deleted-pod":          func(f *fixture) { f.podStatus = 404 },
		"pod-read-denied":      func(f *fixture) { f.podStatus = 403 },
		"pod-replacement":      func(f *fixture) { f.pod["metadata"].(map[string]any)["uid"] = "replacement" },
		"terminating-pod":      func(f *fixture) { f.pod["metadata"].(map[string]any)["deletionTimestamp"] = "2026-01-01T00:00:00Z" },
		"pod-account-mismatch": func(f *fixture) { f.pod["spec"].(map[string]any)["serviceAccountName"] = "other" },
		"store-outage":         func(f *fixture) { f.s.err = errors.New("failure") },
		"role-denied":          func(f *fixture) { f.s.role = "no-access" },
		"revoked-agent":        func(f *fixture) { f.s.status = "revoked" },
		"reviewer-unavailable": func(f *fixture) { os.Remove(f.r.config.ReviewerTokenFile) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); err != nil {
				t.Fatal("positive control failed")
			}
			mutate(f)
			if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); err == nil {
				t.Fatal("denied case admitted")
			}
		})
	}
}

func TestTimeoutTLSAndCredentialRotation(t *testing.T) {
	t.Run("configured-timeout", func(t *testing.T) {
		f := setup(t)
		cfg := f.r.config
		cfg.TimeoutSeconds = 1
		r, err := New(cfg, f.s)
		if err != nil {
			t.Fatal(err)
		}
		f.delay = 3 * time.Second
		started := time.Now()
		if _, err := r.ResolveForProxy(context.Background(), token(f.c), ""); err == nil {
			t.Fatal("configured timeout admitted")
		}
		if time.Since(started) >= 2500*time.Millisecond {
			t.Fatal("verifier ignored configured timeout")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := setup(t)
		f.delay = time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := f.r.ResolveForProxy(ctx, token(f.c), ""); err == nil {
			t.Fatal("timeout admitted")
		}
	})
	t.Run("untrusted-TLS", func(t *testing.T) {
		f := setup(t)
		other := httptest.NewTLSServer(http.NotFoundHandler())
		defer other.Close()
		f.r.config.APIServer = other.URL
		// Replace trust with an empty set. A TLS fixture may reuse the same test certificate.
		f.r.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = nil
		if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); err == nil {
			t.Fatal("untrusted TLS admitted")
		}
	})
	t.Run("rotation", func(t *testing.T) {
		f := setup(t)
		f.reviewer = "rotated"
		os.WriteFile(f.r.config.ReviewerTokenFile, []byte(f.reviewer), 0600)
		if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("vault-hint", func(t *testing.T) {
		f := setup(t)
		if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), "other"); !errors.Is(err, brokercore.ErrVaultHintMismatch) {
			t.Fatal("vault hint changed mapping")
		}
	})
	t.Run("legacy-tokens", func(t *testing.T) {
		f := setup(t)
		for _, raw := range []string{"", "av-standing-token", "a.b.c", strings.Repeat("x", 32769)} {
			if _, err := f.r.ResolveForProxy(context.Background(), raw, ""); err == nil {
				t.Fatal("malformed/static token admitted")
			}
		}
		if f.calls.Load() != 0 {
			t.Fatal("invalid proofs reached verifier")
		}
	})
}

func TestInvalidConfiguration(t *testing.T) {
	f := setup(t)
	for name, mutate := range map[string]func(*Config){
		"http":      func(c *Config) { c.APIServer = "http://api" },
		"userinfo":  func(c *Config) { c.APIServer = "https://user:pass@api" },
		"path":      func(c *Config) { c.APIServer = "https://api/path" },
		"timeout":   func(c *Config) { c.TimeoutSeconds = -1 },
		"lifetime":  func(c *Config) { c.MaxTokenLifetimeSeconds = 86400 },
		"issuer":    func(c *Config) { c.Issuer = "" },
		"audience":  func(c *Config) { c.Audience = "" },
		"ambiguous": func(c *Config) { c.Bindings = append(c.Bindings, c.Bindings[0]) },
		"ca":        func(c *Config) { c.CAFile = "/missing" },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.r.config
			mutate(&c)
			if _, err := New(c, f.s); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	for _, raw := range []string{`{"typo":true}`, `{} {}`, `not-json`} {
		p := filepath.Join(t.TempDir(), "config")
		os.WriteFile(p, []byte(raw), 0600)
		if _, err := LoadConfig(p); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestExpiryAndCancellationDuringStoreLookup(t *testing.T) {
	for _, mode := range []string{"expiry", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			now := time.Now()
			f.r.now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.s.onRole = func() {
				if mode == "expiry" {
					now = time.Unix(f.c.Expires, 0)
				} else {
					cancel()
				}
			}
			if _, err := f.r.ResolveForProxy(ctx, token(f.c), ""); !errors.Is(err, brokercore.ErrInvalidSession) {
				t.Fatal("proof expired or canceled during final store lookup was admitted")
			}
		})
	}
}

func TestLoadConfigRejectsOversizeValidPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// The valid prefix is followed by enough whitespace to hide trailing content
	// behind a one-megabyte artificial EOF in a streaming decoder.
	data := "{}" + strings.Repeat(" ", 1<<20) + `{"issuer":"ignored"}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

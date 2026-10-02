package workloadidentity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// poolFixture serves the cluster's signing keys and one live Pod. Tokens are
// really signed, so the local verification path is exercised end to end.
type poolFixture struct {
	r          *Resolver
	key        *rsa.PrivateKey
	kid        string
	c          claims
	pod        map[string]any
	podStatus  int
	jwksCalls  atomic.Int64
	reviewSeen atomic.Bool
	start      time.Time
}

var workerIP = netip.MustParseAddr("10.244.0.9")

func setupPool(t *testing.T) *poolFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &poolFixture{key: key, kid: "cluster-key-1", podStatus: 200, start: time.Now().Add(-time.Minute)}
	f.c.Issuer, f.c.Subject, f.c.Audience = "https://issuer.test", "system:serviceaccount:pool:worker", []string{"gatehouse"}
	f.c.Issued = time.Now().Unix() - 1
	f.c.Expires = f.c.Issued + 600
	f.c.Kubernetes.Namespace = "pool"
	f.c.Kubernetes.ServiceAccount.Name, f.c.Kubernetes.ServiceAccount.UID = "worker", "account-uid"
	f.c.Kubernetes.Pod.Name, f.c.Kubernetes.Pod.UID = "worker-abc", "pod-uid"
	controller := true
	f.pod = map[string]any{
		"metadata": map[string]any{"name": "worker-abc", "namespace": "pool", "uid": "pod-uid",
			"ownerReferences": []any{map[string]any{"uid": "pool-controller-uid", "controller": controller}}},
		"spec": map[string]any{"serviceAccountName": "worker", "activeDeadlineSeconds": 1800},
		"status": map[string]any{"phase": "Running", "podIP": workerIP.String(), "startTime": f.start.UTC().Format(time.RFC3339),
			"containerStatuses": []any{map[string]any{"name": "agent", "restartCount": 0, "state": map[string]any{"running": map[string]any{}}}}},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer reviewer" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/openid/v1/jwks":
			f.jwksCalls.Add(1)
			e := big.NewInt(int64(f.key.E)).Bytes()
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
		case "/api/v1/namespaces/pool/pods/worker-abc":
			w.WriteHeader(f.podStatus)
			json.NewEncoder(w).Encode(f.pod)
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			f.reviewSeen.Store(true)
			w.WriteHeader(500)
		default:
			t.Error("unexpected API path", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "reviewer")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
	os.WriteFile(tokenFile, []byte("reviewer"), 0600)
	c := Config{APIServer: srv.URL, CAFile: caFile, ReviewerTokenFile: tokenFile, Issuer: f.c.Issuer, Audience: "gatehouse",
		Bindings: []Binding{{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "account-uid", AgentID: "agent", VaultID: "vault",
			OwnerUIDs: []string{"pool-controller-uid"}, ContainerName: "agent", MaxPodSeconds: 3600, Pool: "database-developers"}}}
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

func (f *poolFixture) token(c claims) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": f.kid, "typ": "JWT"})
	payload, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAttestAdmitsPoolPodWithItsDeadline(t *testing.T) {
	f := setupPool(t)
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	if scope.AgentID != "agent" || scope.WorkloadID != "pod-uid" || scope.VaultName != "allowed" || scope.Pool != "database-developers" {
		t.Fatalf("scope %+v", scope)
	}
	// activeDeadlineSeconds (1800) is earlier than the binding's 3600.
	if want := f.start.Truncate(time.Second).Add(1800 * time.Second); !scope.NotAfter.Equal(want) {
		t.Fatalf("NotAfter %v, want %v", scope.NotAfter, want)
	}
	if f.reviewSeen.Load() {
		t.Fatal("pool admission used TokenReview instead of local verification")
	}
	// Keys are cached: a second admission fetches no keys.
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil || f.jwksCalls.Load() != 1 {
		t.Fatalf("err %v, key fetches %d", err, f.jwksCalls.Load())
	}
}

func TestAttestRefusals(t *testing.T) {
	cases := map[string]func(f *poolFixture) (string, netip.Addr){
		"stolen token from another address": func(f *poolFixture) (string, netip.Addr) {
			return f.token(f.c), netip.MustParseAddr("10.244.0.77")
		},
		"loopback peer": func(f *poolFixture) (string, netip.Addr) { return f.token(f.c), netip.MustParseAddr("127.0.0.1") },
		"no peer":       func(f *poolFixture) (string, netip.Addr) { return f.token(f.c), netip.Addr{} },
		"Pod outside the pool": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "other-controller", "controller": true}}
			return f.token(f.c), workerIP
		},
		"owner that is not the controller": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "pool-controller-uid", "controller": false}}
			return f.token(f.c), workerIP
		},
		"deleted Pod": func(f *poolFixture) (string, netip.Addr) {
			f.podStatus = 404
			return f.token(f.c), workerIP
		},
		"terminating Pod": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
			return f.token(f.c), workerIP
		},
		"replaced Pod with the same name": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["uid"] = "new-pod-uid"
			return f.token(f.c), workerIP
		},
		"past its deadline": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["startTime"] = time.Now().Add(-31 * time.Minute).UTC().Format(time.RFC3339)
			return f.token(f.c), workerIP
		},
		"worker container restarted": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["containerStatuses"] = []any{map[string]any{"name": "agent", "restartCount": 1, "state": map[string]any{"running": map[string]any{}}}}
			return f.token(f.c), workerIP
		},
		"not running": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["phase"] = "Pending"
			return f.token(f.c), workerIP
		},
		"wrong audience": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Audience = []string{"other"}
			return f.token(c), workerIP
		},
		"expired token": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Issued, c.Expires = time.Now().Unix()-700, time.Now().Unix()-100
			return f.token(c), workerIP
		},
		"other account": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Kubernetes.ServiceAccount.UID = "other-account"
			return f.token(c), workerIP
		},
		"forged signature": func(f *poolFixture) (string, netip.Addr) {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			real := f.key
			f.key = other
			tok := f.token(f.c)
			f.key = real
			return tok, workerIP
		},
		"unknown key id": func(f *poolFixture) (string, netip.Addr) {
			real := f.kid
			f.kid = "rotated-away"
			tok := f.token(f.c)
			f.kid = real
			return tok, workerIP
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupPool(t)
			tok, peer := mutate(f)
			if scope, err := f.r.Attest(context.Background(), tok, peer); err == nil || scope != nil {
				t.Fatalf("admitted: %+v", scope)
			}
		})
	}
}

func TestPoolBindingNeverAdmittedWithoutPeer(t *testing.T) {
	f := setupPool(t)
	if scope, err := f.r.ResolveForProxy(context.Background(), f.token(f.c), ""); err == nil || scope != nil {
		t.Fatal("a pool binding was admitted without its peer address")
	}
}

func TestPoolBindingValidation(t *testing.T) {
	base := Binding{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "u", AgentID: "a", VaultID: "v", OwnerUIDs: []string{"o"}, MaxPodSeconds: 1800}
	for name, mutate := range map[string]func(*Binding){
		"Pod UID pinned":    func(b *Binding) { b.PodUID = "p" },
		"lifetime too long": func(b *Binding) { b.MaxPodSeconds = 9 * 3600 },
		"lifetime missing":  func(b *Binding) { b.MaxPodSeconds = 0 },
		"empty owner":       func(b *Binding) { b.OwnerUIDs = []string{""} },
		"bad container":     func(b *Binding) { b.ContainerName = "Bad Name" },
		"bad pool name":     func(b *Binding) { b.Pool = "Pool A" },
	} {
		b := base
		mutate(&b)
		f := setupPool(t)
		c := f.r.config
		c.Bindings = []Binding{b}
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

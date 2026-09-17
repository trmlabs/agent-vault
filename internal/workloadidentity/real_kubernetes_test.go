//go:build realkubernetes

package workloadidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var workloadKubeconfig = flag.String("workload-kubeconfig", "", "isolated kubeconfig for kind-credential-proxy-identity (required with realkubernetes)")

// TestRealKubernetesProjectedIdentity uses an explicitly isolated local kind
// API. It creates disposable resources and waits for a real 600-second proof
// to expire. HTTP/PG listeners are real; destinations and lease issuance remain
// synthetic. No part of this test establishes production network isolation.
func TestRealKubernetesProjectedIdentity(t *testing.T) {
	if *workloadKubeconfig == "" {
		t.Fatal("pass -args -workload-kubeconfig /path/to/isolated/kubeconfig")
	}
	kube := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", *workloadKubeconfig, "--context", "kind-credential-proxy-identity"}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("kubectl operation %q failed (output withheld): %v", args[0], err)
		}
		return out
	}
	var kubeconfig struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
				CA     string `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if json.Unmarshal(kube("config", "view", "--raw", "--minify", "-o", "json"), &kubeconfig) != nil || len(kubeconfig.Clusters) != 1 {
		t.Fatal("cannot read isolated cluster configuration")
	}
	api := kubeconfig.Clusters[0].Cluster
	u, err := url.Parse(api.Server)
	if err != nil || u.Scheme != "https" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		t.Fatal("real identity test requires a loopback kind API")
	}
	ns := fmt.Sprintf("identity-%d", time.Now().UnixNano())
	kube("create", "namespace", ns)
	t.Cleanup(func() {
		// Deletion is scoped to resources created by this test. Never emit tokens
		// or kubectl output, including during cleanup errors.
		for _, args := range [][]string{{"delete", "namespace", ns, "--wait=false"}, {"delete", "clusterrolebinding", ns}, {"delete", "clusterrole", ns}} {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", *workloadKubeconfig, "--context", "kind-credential-proxy-identity"}, args...)...).Run()
			cancel()
			if err != nil {
				t.Errorf("disposable identity resource cleanup failed: %s", args[1])
			}
		}
	})
	for _, name := range []string{"agent", "other", "reviewer"} {
		kube("-n", ns, "create", "serviceaccount", name)
	}
	kube("create", "clusterrole", ns, "--verb=create", "--resource=tokenreviews.authentication.k8s.io")
	kube("create", "clusterrolebinding", ns, "--clusterrole="+ns, "--serviceaccount="+ns+":reviewer")
	kube("-n", ns, "create", "role", "pod-check", "--verb=get", "--resource=pods")
	kube("-n", ns, "create", "rolebinding", "pod-check", "--role=pod-check", "--serviceaccount="+ns+":reviewer")
	dir := t.TempDir()
	ca, err := base64.StdEncoding.DecodeString(api.CA)
	if err != nil {
		t.Fatal("invalid cluster trust")
	}
	caPath, reviewerPath := filepath.Join(dir, "ca"), filepath.Join(dir, "reviewer")
	if os.WriteFile(caPath, ca, 0600) != nil || os.WriteFile(reviewerPath, kube("-n", ns, "create", "token", "reviewer", "--duration=15m"), 0600) != nil {
		t.Fatal("cannot write test verifier trust")
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if json.Unmarshal(kube("get", "--raw", "/.well-known/openid-configuration"), &discovery) != nil {
		t.Fatal("cannot read issuer")
	}
	uid := strings.TrimSpace(string(kube("-n", ns, "get", "serviceaccount", "agent", "-o", "jsonpath={.metadata.uid}")))
	store := &fakeStore{status: "active", role: "proxy"}
	cfg := Config{APIServer: api.Server, CAFile: caPath, ReviewerTokenFile: reviewerPath, Issuer: discovery.Issuer, Audience: "credential-proxy", MaxTokenLifetimeSeconds: 600, Bindings: []Binding{{Namespace: ns, ServiceAccount: "agent", ServiceAccountUID: uid, AgentID: "agent", VaultID: "vault"}}}
	r, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	createPod := func(name, account string) {
		t.Helper()
		manifest := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": ns}, "spec": map[string]any{
			"serviceAccountName": account, "automountServiceAccountToken": false, "restartPolicy": "Never",
			"containers": []any{map[string]any{"name": "agent", "image": "busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0", "command": []string{"sleep", "1200"}, "volumeMounts": []any{map[string]any{"name": "proof", "mountPath": "/proof", "readOnly": true}}, "resources": map[string]any{"requests": map[string]string{"cpu": "10m", "memory": "16Mi"}, "limits": map[string]string{"cpu": "100m", "memory": "32Mi"}}}},
			"volumes":    []any{map[string]any{"name": "proof", "projected": map[string]any{"sources": []any{map[string]any{"serviceAccountToken": map[string]any{"path": "allowed", "audience": "credential-proxy", "expirationSeconds": 600}}, map[string]any{"serviceAccountToken": map[string]any{"path": "wrong", "audience": "wrong-audience", "expirationSeconds": 600}}}}}},
		}}
		b, _ := json.Marshal(manifest)
		p := filepath.Join(dir, name+".json")
		if os.WriteFile(p, b, 0600) != nil {
			t.Fatal("cannot write disposable pod manifest")
		}
		kube("apply", "-f", p)
		kube("-n", ns, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=75s")
	}
	proofFor := func(name, path string) string {
		return strings.TrimSpace(string(kube("-n", ns, "exec", name, "--", "cat", "/proof/"+path)))
	}
	createPod("expiry", "agent")
	expiryProof := proofFor("expiry", "allowed")
	var expiry claims
	parts := strings.Split(expiryProof, ".")
	if len(parts) != 3 {
		t.Fatal("invalid projected proof")
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(b, &expiry) != nil {
		t.Fatal("invalid projected claims")
	}
	if _, err := r.ResolveForProxy(context.Background(), expiryProof, ""); err != nil {
		t.Fatal("runtime-issued expiry positive control denied")
	}
	createPod("run", "agent")
	validProof, wrongAudience := proofFor("run", "allowed"), proofFor("run", "wrong")
	createPod("other", "other")
	wrongAccount := proofFor("other", "allowed")
	t.Logf("real Kubernetes proof lifetime=%ds; issuer/audience/account verified; API online; no standing agent token", expiry.Expires-expiry.Issued)
	// Same proof succeeds more than once: document bearer replay honestly.
	for i := 0; i < 2; i++ {
		if _, err := r.ResolveForProxy(context.Background(), validProof, ""); err != nil {
			t.Fatal("valid bearer proof refused")
		}
	}
	exerciseIngress(t, r, validProof, []ingressDenial{
		{"standing-token", func() {}, func() string { return "standing-agent-token" }},
		{"wrong-issuer", func() { r.config.Issuer = "https://undeclared.invalid" }, func() string { return validProof }},
		{"wrong-audience", func() { r.config.Issuer = discovery.Issuer }, func() string { return wrongAudience }},
		{"wrong-account", func() {}, func() string { return wrongAccount }},
		{"removed-grant", func() { store.role = "" }, func() string { return validProof }},
		{"revoked-agent", func() { store.role = "proxy"; store.status = "revoked" }, func() string { return validProof }},
		{"verifier-outage", func() { store.status = "active"; r.config.APIServer = "https://127.0.0.1:1" }, func() string { return validProof }},
		{"deleted-pod", func() {
			r.config.APIServer = api.Server
			kube("-n", ns, "delete", "pod", "run", "--wait=true", "--timeout=45s")
		}, func() string { return validProof }},
		{"same-name-replacement-old-proof", func() { createPod("run", "agent") }, func() string { return validProof }},
	})
	replacement := proofFor("run", "allowed")
	if scope, err := r.ResolveForProxy(context.Background(), replacement, ""); err != nil || scope.WorkloadID == "" {
		t.Fatal("replacement pod's new proof denied")
	}
	// Keep the expiry pod alive. This checks actual elapsed-time expiration of
	// a runtime-issued token, rather than mutating a clock or JWT claims.
	remaining := time.Until(time.Unix(expiry.Expires, 0).Add(time.Second))
	if remaining > 0 {
		t.Logf("waiting %s for actual projected-token expiry", remaining.Round(time.Second))
		timer := time.NewTimer(remaining)
		<-timer.C
	}
	if _, err := r.ResolveForProxy(context.Background(), expiryProof, ""); err == nil {
		t.Fatal("expired real proof admitted")
	}
	fresh := proofFor("expiry", "allowed")
	if _, err := r.ResolveForProxy(context.Background(), fresh, ""); err != nil {
		t.Fatal("rotated live pod proof denied after old proof expired")
	}
	exerciseIngress(t, r, fresh, []ingressDenial{{"expired-projected-proof", func() {}, func() string { return expiryProof }}})
	t.Log("real projected proof, both ingress admissions, denials, pod replacement, expiry and projection rotation passed; bearer replay remains possible")
}

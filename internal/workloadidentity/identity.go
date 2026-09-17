// Package workloadidentity admits projected Kubernetes service-account tokens.
// It never exchanges them for a standing broker token or caches authentication.
// These are bearer proofs: possession permits replay until expiry or revocation.
package workloadidentity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// Binding maps one account to existing broker authorization records. PodUID
// optionally restricts admission to one pod; all pods are checked live by UID.
type Binding struct {
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"serviceAccount"`
	ServiceAccountUID string `json:"serviceAccountUID"`
	PodUID            string `json:"podUID"`
	AgentID           string `json:"agentID"`
	VaultID           string `json:"vaultID"`
}

// Config selects one Kubernetes trust domain and explicit workload grants.
// Empty API/CA/reviewer paths select the standard in-cluster endpoints.
type Config struct {
	APIServer               string    `json:"apiServer"`
	CAFile                  string    `json:"caFile"`
	ReviewerTokenFile       string    `json:"reviewerTokenFile"`
	Issuer                  string    `json:"issuer"`
	Audience                string    `json:"audience"`
	TimeoutSeconds          int       `json:"timeoutSeconds"`
	MaxTokenLifetimeSeconds int64     `json:"maxTokenLifetimeSeconds"`
	Bindings                []Binding `json:"bindings"`
}

// Store supplies current broker identity and grant state for every decision.
type Store interface {
	GetAgentByID(context.Context, string) (*store.Agent, error)
	GetVaultByID(context.Context, string) (*store.Vault, error)
	GetVaultRole(context.Context, string, string) (string, error)
}

// Resolver verifies each proof online and implements both proxy admissions.
type Resolver struct {
	config Config
	client *http.Client
	store  Store
	now    func() time.Time
}

var _ brokercore.SessionResolver = (*Resolver)(nil)

// LoadConfig reads a bounded JSON policy and rejects unknown fields.
func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open workload identity configuration")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return c, errors.New("workload identity configuration exceeds size limit or cannot be read")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid workload identity configuration")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing workload identity configuration")
	}
	return c, nil
}

// New validates policy and builds a TLS-verifying client with no redirect or
// environment-proxy fallback. It never retains a positive authentication cache.
func New(c Config, s Store) (*Resolver, error) {
	if c.APIServer == "" {
		c.APIServer = "https://kubernetes.default.svc"
	}
	if c.CAFile == "" {
		c.CAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	}
	if c.ReviewerTokenFile == "" {
		c.ReviewerTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	u, err := url.Parse(c.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("workload identity apiServer must be an HTTPS origin")
	}
	if s == nil || c.CAFile == "" || c.ReviewerTokenFile == "" || c.Issuer == "" || c.Audience == "" || len(c.Bindings) == 0 {
		return nil, errors.New("workload identity requires trust, reviewer token, issuer, audience, store and bindings")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 5
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 {
		return nil, errors.New("workload identity timeoutSeconds must be between 1 and 30")
	}
	if c.MaxTokenLifetimeSeconds == 0 {
		c.MaxTokenLifetimeSeconds = 3600
	}
	if c.MaxTokenLifetimeSeconds < 600 || c.MaxTokenLifetimeSeconds > 3600 {
		return nil, errors.New("workload identity maxTokenLifetimeSeconds must be between 600 and 3600")
	}
	seen := map[string]bool{}
	for _, b := range c.Bindings {
		if !pathSegment(b.Namespace) || !pathSegment(b.ServiceAccount) || b.ServiceAccountUID == "" || b.AgentID == "" || b.VaultID == "" {
			return nil, errors.New("workload identity binding requires namespace, account, account UID, agent and vault")
		}
		key := b.Namespace + ":" + b.ServiceAccount
		if seen[key] {
			return nil, errors.New("ambiguous workload identity binding")
		}
		seen[key] = true
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("cannot read workload identity CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid workload identity CA")
	}
	c.APIServer = strings.TrimSuffix(c.APIServer, "/")
	c.Bindings = append([]Binding(nil), c.Bindings...)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return &Resolver{config: c, store: s, now: time.Now, client: &http.Client{
		Timeout: time.Duration(c.TimeoutSeconds) * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func pathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

type claims struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	Expires    int64    `json:"exp"`
	Issued     int64    `json:"iat"`
	NotBefore  int64    `json:"nbf"`
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
		Pod struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

type review struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Error         string   `json:"error"`
		Audiences     []string `json:"audiences"`
		User          struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

// ResolveForProxy verifies proof for every admission and reauthorization. No
// local/session-token fallback is allowed when this resolver is configured.
func (r *Resolver) ResolveForProxy(ctx context.Context, token, vaultHint string) (*brokercore.ProxyScope, error) {
	deny := brokercore.ErrInvalidSession
	if len(token) == 0 || len(token) > 32768 {
		return nil, deny
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return nil, deny
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, deny
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return nil, deny
	}
	// This release intentionally accepts only single-audience broker proofs,
	// a narrower policy than standard JWT audience membership.
	now := r.now().Unix()
	if c.Issuer != r.config.Issuer || !exactly(c.Audience, r.config.Audience) || c.Expires <= now || c.Issued <= 0 || c.Issued > now || c.NotBefore > now || c.Expires <= c.Issued || c.Expires-c.Issued > r.config.MaxTokenLifetimeSeconds {
		return nil, deny
	}
	k := c.Kubernetes
	if k.Pod.UID == "" || !pathSegment(k.Pod.Name) || !pathSegment(k.Namespace) || c.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
		return nil, deny
	}
	var binding *Binding
	for i := range r.config.Bindings {
		b := &r.config.Bindings[i]
		if b.Namespace == k.Namespace && b.ServiceAccount == k.ServiceAccount.Name && b.ServiceAccountUID == k.ServiceAccount.UID && (b.PodUID == "" || b.PodUID == k.Pod.UID) {
			binding = b
			break
		}
	}
	if binding == nil {
		return nil, deny
	}
	// Claims above only narrow policy. They become authenticated exclusively by
	// a successful online TokenReview of the exact original token below.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	var req review
	req.APIVersion, req.Kind = "authentication.k8s.io/v1", "TokenReview"
	req.Spec.Token, req.Spec.Audiences = token, []string{r.config.Audience}
	body, _ := json.Marshal(req)
	var verified review
	if r.api(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", body, &verified) != nil {
		return nil, deny
	}
	s := verified.Status
	if verified.APIVersion != req.APIVersion || verified.Kind != req.Kind || !s.Authenticated || s.Error != "" || !exactly(s.Audiences, r.config.Audience) || s.User.Username != c.Subject || s.User.UID != k.ServiceAccount.UID || !exactly(s.User.Extra["authentication.kubernetes.io/pod-uid"], k.Pod.UID) || !exactly(s.User.Extra["authentication.kubernetes.io/pod-name"], k.Pod.Name) {
		return nil, deny
	}
	// TokenReview permits a deletion grace period. An explicit Pod read denies
	// terminating/deleted pods immediately and pins the current object's UID.
	var pod struct {
		Metadata struct {
			UID               string  `json:"uid"`
			Name              string  `json:"name"`
			Namespace         string  `json:"namespace"`
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
	}
	if r.api(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(k.Namespace)+"/pods/"+url.PathEscape(k.Pod.Name), nil, &pod) != nil || pod.Metadata.UID != k.Pod.UID || pod.Metadata.Name != k.Pod.Name || pod.Metadata.Namespace != k.Namespace || pod.Metadata.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != k.ServiceAccount.Name {
		return nil, deny
	}
	if c.Expires <= r.now().Unix() {
		return nil, deny
	}
	a, err := r.store.GetAgentByID(ctx, binding.AgentID)
	if err != nil || a == nil || a.ID != binding.AgentID || a.Status != "active" || a.RevokedAt != nil {
		return nil, deny
	}
	v, err := r.store.GetVaultByID(ctx, binding.VaultID)
	if err != nil || v == nil || v.ID != binding.VaultID {
		return nil, brokercore.ErrVaultAccessDenied
	}
	if vaultHint != "" && vaultHint != v.Name {
		return nil, brokercore.ErrVaultHintMismatch
	}
	role, err := r.store.GetVaultRole(ctx, a.ID, v.ID)
	if err != nil || (role != "proxy" && role != "member" && role != "admin") {
		return nil, brokercore.ErrVaultAccessDenied
	}
	// Store calls may consume the remainder of the proof lifetime or timeout.
	// Never return an authorized scope after either deadline elapsed.
	if ctx.Err() != nil || c.Expires <= r.now().Unix() {
		return nil, deny
	}
	return &brokercore.ProxyScope{AgentID: a.ID, WorkloadID: k.Pod.UID, VaultID: v.ID, VaultName: v.Name, VaultRole: role}, nil
}

func exactly(values []string, value string) bool { return len(values) == 1 && values[0] == value }

func (r *Resolver) api(ctx context.Context, method, path string, body []byte, out any) error {
	// Re-read the broker's projected reviewer token so kubelet rotation works.
	credential, err := os.ReadFile(r.config.ReviewerTokenFile)
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	bearer := strings.TrimSpace(string(credential))
	if bearer == "" || strings.ContainsAny(bearer, "\r\n") {
		return errors.New("workload verifier unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, method, r.config.APIServer+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("workload verifier refused request (status %d)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, out) != nil {
		return errors.New("invalid workload verifier response")
	}
	return nil
}

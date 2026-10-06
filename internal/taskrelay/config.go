// Package taskrelay keeps workload proofs outside an untrusted task sandbox.
// The operator supplies an immutable, per-task pairing; network isolation must
// independently prevent sandbox traffic from bypassing this relay.
package taskrelay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// FixedConfig is operator-owned. None of these fields may come from requests.
type FixedConfig struct {
	TaskID           string           `json:"taskID"`
	Deadline         time.Time        `json:"deadline"`
	Sandbox          SandboxConfig    `json:"sandbox"`
	Kubernetes       KubernetesConfig `json:"kubernetes"`
	TLSCertFile      string           `json:"tlsCertFile"`
	TLSKeyFile       string           `json:"tlsKeyFile"`
	AuditFile        string           `json:"auditFile"`
	Connect          *ConnectConfig   `json:"connect,omitempty"`
	Postgres         *PostgresConfig  `json:"postgres,omitempty"`
	PostgresBindings []PostgresConfig `json:"postgresBindings,omitempty"`
	// PostgresListener, in shared mode only, is one port for every catalog
	// database; see PostgresListenerConfig.
	PostgresListener *PostgresListenerConfig `json:"postgresListener,omitempty"`
	Browser          *BrowserConfig          `json:"browser,omitempty"`
	// Self runs the relay as a sidecar in the worker's own Pod: loopback,
	// plaintext listeners only, and no Kubernetes pairing, because the broker
	// verifies this Pod's token and address on every connection.
	Self bool `json:"self,omitempty"`
	// Shared runs the relay as one proxy for many agent Pods; see SharedConfig.
	Shared *SharedConfig `json:"shared,omitempty"`
	// TLS, in shared mode only, serves every listener but AdminListen in TLS
	// with a broker-issued certificate; see ServingTLSConfig.
	TLS *ServingTLSConfig `json:"tls,omitempty"`
	// AdminListen, in shared mode only, serves GET /v1/activity in plaintext:
	// when each agent Pod last used this replica, for the idle janitor. A
	// network policy must admit only the janitor to it.
	AdminListen string `json:"adminListen,omitempty"`
	// ActivityRetentionSeconds is how long the activity report keeps a
	// Sandbox after its last use (default a day). The janitor refuses a
	// retention shorter than its idle time.
	ActivityRetentionSeconds int64 `json:"activityRetentionSeconds,omitempty"`
	// DurableActivity keeps activity in the broker's shared store; see
	// DurableActivityConfig.
	DurableActivity *DurableActivityConfig `json:"durableActivity,omitempty"`
}
type SandboxConfig struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	UID           string `json:"uid"`
	PodIP         string `json:"podIP"`
	ContainerName string `json:"containerName"`
}
type KubernetesConfig struct {
	APIURL            string `json:"apiURL"`
	CAFile            string `json:"caFile"`
	ReviewerTokenFile string `json:"reviewerTokenFile"`
}
type UpstreamConfig struct {
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
	CAFile     string `json:"caFile"`
	ProofFile  string `json:"proofFile"`
	Audience   string `json:"audience"`
	// SessionFile, in self mode, holds the Claude runner's session token. The
	// relay sends it to the broker on each CONNECT, and on each PostgreSQL
	// connection as a preamble line ahead of the startup it authors, so the
	// broker can verify the person behind the session. A missing or empty
	// file sends nothing.
	SessionFile string `json:"sessionFile,omitempty"`
}
type ConnectConfig struct {
	Listen         string         `json:"listen"`
	Upstream       UpstreamConfig `json:"upstream"`
	AllowedTargets []string       `json:"allowedTargets"`
}
type PostgresConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Database    string         `json:"database"`
	User        string         `json:"user"`
	Placeholder string         `json:"placeholder"`
}

// PostgresListenerConfig is one PostgreSQL port routed by the startup
// packet's database parameter. Databases is the route table, rendered from
// the catalog: a name outside it is refused before the broker is dialed, and a
// name in it goes to the one upstream, which authorizes it per pool. There is
// no fixed route count.
type PostgresListenerConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Databases   []string       `json:"databases"`
	User        string         `json:"user"`
	Placeholder string         `json:"placeholder"`
}

// route is the binding for one catalog database on this listener.
func (l *PostgresListenerConfig) route(database string) PostgresConfig {
	return PostgresConfig{Listen: l.Listen, Upstream: l.Upstream, Database: database, User: l.User, Placeholder: l.Placeholder}
}

type BrowserConfig struct {
	Listen   string         `json:"listen"`
	Upstream UpstreamConfig `json:"upstream"`
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}$`)
var containerName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var errConfig = errors.New("invalid fixed task relay configuration")

const maxConfigBytes = 16 << 20

// LoadConfig rejects unknown fields, trailing data and oversized configuration.
func LoadConfig(path string) (FixedConfig, error) {
	var c FixedConfig
	// A shared proxy's route table lists every catalog database, so the bound
	// is sized for tens of thousands of names, not for one binding.
	b, err := readBoundedFile(path, maxConfigBytes)
	if err != nil {
		return c, errConfig
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errConfig
	}
	// A sidecar's config is static in the Pod template, so its relay lifetime
	// starts with the container; the broker enforces the Pod's real deadline.
	if c.Self && c.Deadline.IsZero() {
		c.Deadline = time.Now().Add(workloadidentity.DefaultSessionCeiling).Add(-time.Minute)
	}
	// A shared proxy serves many agents for as long as it runs; each agent's
	// own deadline comes from its Pod.
	if c.Shared != nil && c.Deadline.IsZero() {
		c.Deadline = time.Now().Add(10 * 365 * 24 * time.Hour)
	}
	return c, c.Validate(time.Now())
}

func (c FixedConfig) Validate(now time.Time) error {
	if (c.AdminListen != "" || c.PostgresListener != nil || c.TLS != nil) && c.Shared == nil {
		return errConfig
	}
	// Activity reaches the broker over the CONNECT upstream.
	if d := c.DurableActivity; d != nil && (c.AdminListen == "" || c.Connect == nil || d.PushSeconds < 0 || d.PushSeconds > 3600) {
		return errConfig
	}
	// Up to a year: retention costs one small entry per Sandbox used.
	if c.ActivityRetentionSeconds != 0 && (c.AdminListen == "" || c.ActivityRetentionSeconds < 60 || c.ActivityRetentionSeconds > 366*24*3600) {
		return errConfig
	}
	if c.Shared != nil {
		return c.validateShared(now)
	}
	if c.Self {
		return c.validateSelf(now)
	}
	if (c.Connect != nil && c.Connect.Upstream.SessionFile != "") || c.Browser != nil && c.Browser.Upstream.SessionFile != "" {
		return errConfig // only a sidecar in the session's own Pod forwards its token
	}
	for _, p := range c.postgresBindings() {
		if p.Upstream.SessionFile != "" {
			return errConfig
		}
	}
	if !containerName.MatchString(c.Sandbox.ContainerName) {
		return errConfig
	}
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.Deadline.After(now.Add(workloadidentity.DefaultSessionCeiling)) {
		return errConfig
	}
	for _, v := range []string{c.Sandbox.Namespace, c.Sandbox.Name, c.Sandbox.UID} {
		if !safeName.MatchString(v) {
			return errConfig
		}
	}
	if net.ParseIP(c.Sandbox.PodIP) == nil || c.TLSCertFile == "" || c.TLSKeyFile == "" || c.AuditFile == "" || c.Kubernetes.CAFile == "" || c.Kubernetes.ReviewerTokenFile == "" {
		return errConfig
	}
	u, e := url.Parse(c.Kubernetes.APIURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errConfig
	}
	used := map[string]bool{}
	check := func(listen string, upstream UpstreamConfig) error {
		if !validAddress(listen) || used[listen] || !validAddress(upstream.Address) || upstream.ServerName == "" || upstream.CAFile == "" || upstream.ProofFile == "" || upstream.Audience == "" {
			return errConfig
		}
		used[listen] = true
		return nil
	}
	if c.Connect != nil {
		if check(c.Connect.Listen, c.Connect.Upstream) != nil || len(c.Connect.AllowedTargets) == 0 || len(c.Connect.AllowedTargets) > 32 {
			return errConfig
		}
		for _, target := range c.Connect.AllowedTargets {
			if !validAddress(target) {
				return errConfig
			}
		}
	}
	if len(c.PostgresBindings) > 8 || (c.Postgres != nil && len(c.PostgresBindings) != 0) {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if check(p.Listen, p.Upstream) != nil || !safeName.MatchString(p.Database) || !safeName.MatchString(p.User) || !safeName.MatchString(p.Placeholder) {
			return errConfig
		}
	}
	if c.Browser != nil && check(c.Browser.Listen, c.Browser.Upstream) != nil {
		return errConfig
	}
	if len(used) == 0 {
		return errConfig
	}
	return nil
}

// validateSelf allows only loopback listeners, no browser and no pairing input.
func (c FixedConfig) validateSelf(now time.Time) error {
	if c.Connect != nil && c.Connect.Upstream.SessionFile != "" && !strings.HasPrefix(c.Connect.Upstream.SessionFile, "/") {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if p.Upstream.SessionFile != "" && !strings.HasPrefix(p.Upstream.SessionFile, "/") {
			return errConfig
		}
	}
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.Deadline.After(now.Add(workloadidentity.DefaultSessionCeiling)) || c.AuditFile == "" || c.Browser != nil ||
		c.Sandbox != (SandboxConfig{}) || c.Kubernetes != (KubernetesConfig{}) || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		return errConfig
	}
	used := map[string]bool{}
	check := func(listen string, upstream UpstreamConfig) error {
		host, _, _ := net.SplitHostPort(listen)
		ip := net.ParseIP(host)
		if !validAddress(listen) || ip == nil || !ip.IsLoopback() || used[listen] || !validAddress(upstream.Address) || upstream.ServerName == "" || upstream.CAFile == "" || upstream.ProofFile == "" || upstream.Audience == "" {
			return errConfig
		}
		used[listen] = true
		return nil
	}
	if c.Connect != nil {
		if check(c.Connect.Listen, c.Connect.Upstream) != nil || len(c.Connect.AllowedTargets) == 0 || len(c.Connect.AllowedTargets) > 32 {
			return errConfig
		}
		for _, target := range c.Connect.AllowedTargets {
			if !validAddress(target) {
				return errConfig
			}
		}
	}
	if len(c.PostgresBindings) > 8 || (c.Postgres != nil && len(c.PostgresBindings) != 0) {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if check(p.Listen, p.Upstream) != nil || !safeName.MatchString(p.Database) || !safeName.MatchString(p.User) || !safeName.MatchString(p.Placeholder) {
			return errConfig
		}
	}
	if len(used) == 0 {
		return errConfig
	}
	return nil
}

// postgresBindings preserves the legacy single binding without mixing authority.
func (c FixedConfig) activityRetention() time.Duration {
	if c.ActivityRetentionSeconds == 0 {
		return defaultActivityRetention
	}
	return time.Duration(c.ActivityRetentionSeconds) * time.Second
}

func (c FixedConfig) postgresBindings() []PostgresConfig {
	if c.Postgres != nil {
		return []PostgresConfig{*c.Postgres}
	}
	return c.PostgresBindings
}

func validAddress(s string) bool {
	host, port, err := net.SplitHostPort(s)
	n, e := strconv.Atoi(port)
	return err == nil && e == nil && n > 0 && n <= 65535 && host != "" && !strings.ContainsAny(host, "\r\n\t /?#@")
}

func readBoundedFile(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errConfig
	}
	return b, nil
}

func clientTLS(caFile, serverName string) (*tls.Config, error) {
	pem, e := readBoundedFile(caFile, 1<<20)
	if e != nil {
		return nil, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errConfig
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}, nil
}

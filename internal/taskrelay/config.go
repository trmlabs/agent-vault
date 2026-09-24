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
	Browser          *BrowserConfig   `json:"browser,omitempty"`
}
type SandboxConfig struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	PodIP     string `json:"podIP"`
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
type BrowserConfig struct {
	Listen   string         `json:"listen"`
	Upstream UpstreamConfig `json:"upstream"`
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}$`)
var errConfig = errors.New("invalid fixed task relay configuration")

// LoadConfig rejects unknown fields, trailing data and oversized configuration.
func LoadConfig(path string) (FixedConfig, error) {
	var c FixedConfig
	b, err := readBoundedFile(path, 64<<10)
	if err != nil {
		return c, errConfig
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errConfig
	}
	return c, c.Validate(time.Now())
}

func (c FixedConfig) Validate(now time.Time) error {
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.Deadline.After(now.Add(8*time.Hour)) {
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

// postgresBindings preserves the legacy single binding without mixing authority.
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

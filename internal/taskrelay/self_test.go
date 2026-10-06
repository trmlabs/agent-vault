package taskrelay

import (
	"context"
	"testing"
	"time"
)

func selfConfig() FixedConfig {
	up := UpstreamConfig{Address: "gatehouse.gatehouse.svc:15443", ServerName: "gatehouse.gatehouse.svc", CAFile: "/ca", ProofFile: "/proof", Audience: "gatehouse"}
	return FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: "/data/audit.jsonl", Self: true,
		PostgresBindings: []PostgresConfig{{Listen: "127.0.0.1:15000", Upstream: up, Database: "core", User: "workload", Placeholder: "gatehouse-relay-placeholder"}}}
}

func TestSelfModeAcceptsLoopbackOnly(t *testing.T) {
	if err := selfConfig().Validate(time.Now()); err != nil {
		t.Fatalf("valid sidecar config refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"listener off loopback": func(c *FixedConfig) { c.PostgresBindings[0].Listen = "0.0.0.0:15000" },
		"pairing input":         func(c *FixedConfig) { c.Sandbox.Name = "other-pod" },
		"kubernetes input":      func(c *FixedConfig) { c.Kubernetes.APIURL = "https://10.0.0.1" },
		"TLS listener files":    func(c *FixedConfig) { c.TLSCertFile = "/tls.crt" },
		"browser":               func(c *FixedConfig) { c.Browser = &BrowserConfig{Listen: "127.0.0.1:16443"} },
		"over a day":            func(c *FixedConfig) { c.Deadline = time.Now().Add(25 * time.Hour) },
		"no audit":              func(c *FixedConfig) { c.AuditFile = "" },
		"no listener":           func(c *FixedConfig) { c.PostgresBindings = nil },
		"relative session file": func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionFile = "token" },
	} {
		c := selfConfig()
		c.PostgresBindings = append([]PostgresConfig(nil), c.PostgresBindings...)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSelfModePeerIsTheSamePod(t *testing.T) {
	v, err := newPairVerifier(selfConfig())
	if err != nil {
		t.Fatal(err)
	}
	if v.check(context.Background(), "127.0.0.1:50000") != nil || !v.peerMatches("[::1]:50000") {
		t.Fatal("loopback peer refused")
	}
	if v.check(context.Background(), "10.244.0.12:50000") == nil || v.peerMatches("10.244.0.12:50000") {
		t.Fatal("another Pod's address admitted")
	}
	expired := selfConfig()
	expired.Deadline = time.Now().Add(-time.Second)
	v, _ = newPairVerifier(expired)
	if v.check(context.Background(), "127.0.0.1:50000") == nil {
		t.Fatal("expired relay admitted")
	}
}

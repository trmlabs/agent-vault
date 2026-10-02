package brokercore

import (
	"errors"
	"testing"
)

func TestFleetReplicaNameNeedsThePodName(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	// A fleet (shared store) never falls back to the audit name or hostname.
	if _, err := FleetReplicaName(env(map[string]string{"DATABASE_URL": "postgres://x", "AGENT_VAULT_AUDIT_REPLICA": "gatehouse-0"})); !errors.Is(err, ErrFleetReplicaName) {
		t.Fatalf("fleet fell back: %v", err)
	}
	if name, err := FleetReplicaName(env(map[string]string{"DATABASE_URL": "postgres://x", "AGENT_VAULT_REPLICA": "gatehouse-1", "AGENT_VAULT_AUDIT_REPLICA": "gatehouse-0"})); err != nil || name != "gatehouse-1" {
		t.Fatalf("fleet name %q %v", name, err)
	}
	// A store URL read from a file is a shared store too.
	if _, err := FleetReplicaName(env(map[string]string{"DATABASE_URL_FILE": "/run/secrets/store-url", "AGENT_VAULT_AUDIT_REPLICA": "gatehouse-0"})); !errors.Is(err, ErrFleetReplicaName) {
		t.Fatalf("file-based store fell back: %v", err)
	}
	// A single broker keeps the older fallback.
	if name, err := FleetReplicaName(env(map[string]string{"AGENT_VAULT_AUDIT_REPLICA": "gatehouse-0"})); err != nil || name != "gatehouse-0" {
		t.Fatalf("single broker name %q %v", name, err)
	}
}

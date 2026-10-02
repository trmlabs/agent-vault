package brokercore

import (
	"errors"
	"os"
	"regexp"
)

var replicaPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// ReplicaName names this broker in the fleet: AGENT_VAULT_REPLICA (set from the
// Pod name by the downward API), then the older AGENT_VAULT_AUDIT_REPLICA, then
// the hostname, which is the Pod name in Kubernetes. Cleanup owners, session
// rows and audit chains all use it.
func ReplicaName(getenv func(string) string) string {
	for _, key := range []string{"AGENT_VAULT_REPLICA", "AGENT_VAULT_AUDIT_REPLICA"} {
		if v := getenv(key); v != "" {
			return v
		}
	}
	host, _ := os.Hostname()
	return host
}

// ErrFleetReplicaName means brokers share a store but this one has no
// AGENT_VAULT_REPLICA. Two replicas that fell back to the same name would
// share cleanup ownership and an audit chain, so a fleet never falls back.
var ErrFleetReplicaName = errors.New("AGENT_VAULT_REPLICA (the Pod name, from the downward API) is required when brokers share a store (DATABASE_URL or DATABASE_URL_FILE)")

// FleetReplicaName is ReplicaName, except that brokers sharing a store
// (DATABASE_URL or DATABASE_URL_FILE set) must name themselves with AGENT_VAULT_REPLICA: no
// fallback to AGENT_VAULT_AUDIT_REPLICA or the hostname.
func FleetReplicaName(getenv func(string) string) (string, error) {
	if getenv("DATABASE_URL") == "" && getenv("DATABASE_URL_FILE") == "" {
		return ReplicaName(getenv), nil
	}
	if v := getenv("AGENT_VAULT_REPLICA"); v != "" {
		return v, nil
	}
	return "", ErrFleetReplicaName
}

// ValidReplicaName reports whether a name is a DNS-style replica name.
func ValidReplicaName(name string) bool { return replicaPattern.MatchString(name) }

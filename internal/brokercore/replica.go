package brokercore

import (
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

// ValidReplicaName reports whether a name is a DNS-style replica name.
func ValidReplicaName(name string) bool { return replicaPattern.MatchString(name) }

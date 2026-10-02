package brokercore

import "testing"

func TestReplicaNamePrecedence(t *testing.T) {
	env := map[string]string{"AGENT_VAULT_REPLICA": "gatehouse-real-databases-1", "AGENT_VAULT_AUDIT_REPLICA": "old"}
	if got := ReplicaName(func(k string) string { return env[k] }); got != "gatehouse-real-databases-1" {
		t.Fatalf("got %q", got)
	}
	delete(env, "AGENT_VAULT_REPLICA")
	if got := ReplicaName(func(k string) string { return env[k] }); got != "old" {
		t.Fatalf("got %q", got)
	}
	if ValidReplicaName("Bad Name") || ValidReplicaName("") || !ValidReplicaName("gatehouse-real-databases-0") {
		t.Fatal("replica name validation")
	}
}

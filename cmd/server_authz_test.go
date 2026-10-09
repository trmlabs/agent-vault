package cmd

import "testing"

func TestRunnerPersonDomains(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	base := map[string]string{"AGENT_VAULT_RUNNER_JWKS_URL": "https://api.anthropic.com/v1/code/.well-known/jwks.json"}

	a, err := loadAuthorization(env(base))
	if err != nil || a.runner == nil || len(a.runner.PersonDomains) != 0 {
		t.Fatalf("unset: %+v %v", a.runner, err)
	}
	with := map[string]string{"AGENT_VAULT_RUNNER_PERSON_DOMAINS": "example.org,example.com"}
	for k, v := range base {
		with[k] = v
	}
	a, err = loadAuthorization(env(with))
	if err != nil || len(a.runner.PersonDomains) != 2 || a.runner.PersonDomains[0] != "example.org" {
		t.Fatalf("set: %+v %v", a.runner, err)
	}
	for _, bad := range []string{"EXAMPLE.org", "example.org, example.com", "*.example.org", "example", ",", "example.org,"} {
		with["AGENT_VAULT_RUNNER_PERSON_DOMAINS"] = bad
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCursorSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": "123,456",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "example.org"}
	a, err := loadAuthorization(env(good))
	if err != nil || a.cursor == nil || a.runner != nil || len(a.cursor.TeamIDs) != 2 || a.cursor.PersonDomains[0] != "example.org" ||
		a.cursor.JWKSURL != "https://api.cursor.com/keys" || a.cursor.Issuer != "https://api.cursor.com" || a.verifier() == nil {
		t.Fatalf("set: %+v %v", a.cursor, err)
	}
	if a, err := loadAuthorization(env(map[string]string{})); err != nil || a.cursor != nil || a.verifier() != nil {
		t.Fatalf("unset: %+v %v", a.cursor, err)
	}
	bad := map[string]string{
		"AGENT_VAULT_CURSOR_TEAM_IDS":       "",
		"AGENT_VAULT_CURSOR_AUDIENCE":       "has space",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "*.example.org",
		"AGENT_VAULT_CURSOR_JWKS_URL":       "http://api.cursor.com/keys",
	}
	for key, value := range bad {
		with := map[string]string{}
		for k, v := range good {
			with[k] = v
		}
		with[key] = value
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%s=%q accepted", key, value)
		}
	}
	for _, teams := range []string{"abc", "123,", "12 3"} {
		with := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": teams}
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("teams %q accepted", teams)
		}
	}
}

// AGENT_VAULT_SANDBOX_PERSON_DOMAINS alone yields a verifier that names
// attested persons; unset, there is none.
func TestSandboxPersonDomains(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	a, err := loadAuthorization(env(nil))
	if err != nil || a.verifier() != nil {
		t.Fatalf("unset: %v", err)
	}
	a, err = loadAuthorization(env(map[string]string{"AGENT_VAULT_SANDBOX_PERSON_DOMAINS": "example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	persons, ok := a.verifier().(interface {
		AttestedPerson(string) (string, error)
	})
	if !ok {
		t.Fatal("verifier names no attested persons")
	}
	if person, err := persons.AttestedPerson("alice.smith@example.org"); err != nil || person != "alice.smith@example.org" {
		t.Fatalf("person %q %v", person, err)
	}
	if _, err := loadAuthorization(env(map[string]string{"AGENT_VAULT_SANDBOX_PERSON_DOMAINS": "*.example.org"})); err == nil {
		t.Fatal("wildcard domain accepted")
	}
}

func TestGraphSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_ENTITLEMENTS": "graph",
		"AGENT_VAULT_GRAPH_TENANT_ID":  "11111111-1111-1111-1111-111111111111",
		"AGENT_VAULT_GRAPH_CLIENT_ID":  "22222222-2222-2222-2222-222222222222",
		"AGENT_VAULT_GRAPH_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token"}
	a, err := loadAuthorization(env(good))
	if err != nil || a.entitlements == nil {
		t.Fatalf("set: %+v %v", a.entitlements, err)
	}
	for key, bad := range map[string]string{
		"AGENT_VAULT_GRAPH_TENANT_ID":  "",
		"AGENT_VAULT_GRAPH_CLIENT_ID":  "22222222-2222-2222-2222-22222222222Z",
		"AGENT_VAULT_GRAPH_TOKEN_FILE": "relative/token",
	} {
		with := map[string]string{}
		for k, v := range good {
			with[k] = v
		}
		with[key] = bad
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%s=%q accepted", key, bad)
		}
	}
	if _, err := loadAuthorization(env(map[string]string{"AGENT_VAULT_ENTITLEMENTS": "graph"})); err == nil {
		t.Error("graph without its settings accepted")
	}
}

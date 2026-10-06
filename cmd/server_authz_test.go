package cmd

import "testing"

func TestRunnerPersonDomains(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	base := map[string]string{"AGENT_VAULT_RUNNER_JWKS_URL": "https://api.anthropic.com/v1/code/.well-known/jwks.json"}

	a, err := loadAuthorization(env(base))
	if err != nil || a.runner == nil || len(a.runner.PersonDomains) != 0 {
		t.Fatalf("unset: %+v %v", a.runner, err)
	}
	with := map[string]string{"AGENT_VAULT_RUNNER_PERSON_DOMAINS": "trmlabs.com,example.com"}
	for k, v := range base {
		with[k] = v
	}
	a, err = loadAuthorization(env(with))
	if err != nil || len(a.runner.PersonDomains) != 2 || a.runner.PersonDomains[0] != "trmlabs.com" {
		t.Fatalf("set: %+v %v", a.runner, err)
	}
	for _, bad := range []string{"TRMLABS.com", "trmlabs.com, example.com", "*.trmlabs.com", "trmlabs", ",", "trmlabs.com,"} {
		with["AGENT_VAULT_RUNNER_PERSON_DOMAINS"] = bad
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCursorSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": "123,456",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "trmlabs.com"}
	a, err := loadAuthorization(env(good))
	if err != nil || a.cursor == nil || a.runner != nil || len(a.cursor.TeamIDs) != 2 || a.cursor.PersonDomains[0] != "trmlabs.com" ||
		a.cursor.JWKSURL != "https://api.cursor.com/keys" || a.cursor.Issuer != "https://api.cursor.com" || a.verifier() == nil {
		t.Fatalf("set: %+v %v", a.cursor, err)
	}
	if a, err := loadAuthorization(env(map[string]string{})); err != nil || a.cursor != nil || a.verifier() != nil {
		t.Fatalf("unset: %+v %v", a.cursor, err)
	}
	bad := map[string]string{
		"AGENT_VAULT_CURSOR_TEAM_IDS":       "",
		"AGENT_VAULT_CURSOR_AUDIENCE":       "has space",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "*.trmlabs.com",
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

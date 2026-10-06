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

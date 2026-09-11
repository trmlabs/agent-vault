package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestDatabaseSubcommandsRegistered(t *testing.T) {
	vault := findSubcommand(rootCmd, "vault")
	if vault == nil {
		t.Fatal("vault command not found")
	}
	db := findSubcommand(vault, "database")
	if db == nil {
		t.Fatal("database command not found under vault")
	}
	// The short alias resolves to the same command.
	if alias, _, err := vault.Find([]string{"db"}); err != nil || alias != db {
		t.Fatalf("expected 'db' alias to resolve to the database command, got %v (err %v)", alias, err)
	}

	for _, name := range []string{"list", "add", "remove"} {
		if findSubcommand(db, name) == nil {
			t.Errorf("expected database subcommand %q to be registered", name)
		}
	}
}

func TestBoolEnvValue(t *testing.T) {
	cases := map[string]bool{
		"1": true, "true": true, "TRUE": true, "t": true,
		"0": false, "false": false, "": false, "nonsense": false,
	}
	for raw, want := range cases {
		t.Setenv("AGENT_VAULT_DB_BROKER", raw)
		if got := boolEnvValue("AGENT_VAULT_DB_BROKER"); got != want {
			t.Errorf("boolEnvValue(%q) = %v, want %v", raw, got, want)
		}
	}
	// An unset variable is false.
	os.Unsetenv("AGENT_VAULT_DB_BROKER")
	if boolEnvValue("AGENT_VAULT_DB_BROKER") {
		t.Error("unset should be false")
	}
}

// TestDatabaseAddRequiresCoreFlags pins that the add command rejects a call
// missing any of the required coordinates before it attempts a session, so an
// operator gets a clear local error rather than a network failure.
func TestDatabaseAddRequiresCoreFlags(t *testing.T) {
	_, err := executeCommand("vault", "database", "add", "--name", "alloy", "--upstream", "h:5432")
	if err == nil {
		t.Fatal("expected an error when --mount and --role are missing")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected a 'required' flag error, got: %v", err)
	}
}

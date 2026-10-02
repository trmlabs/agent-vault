package httpcatalog

import (
	"os"
	"testing"
)

// This package's tests use plain role names; tests of the environment rule
// set Environment or clear this themselves.
func TestMain(m *testing.M) {
	rolesWithoutEnvironment = true
	os.Exit(m.Run())
}

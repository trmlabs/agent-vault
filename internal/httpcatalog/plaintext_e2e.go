//go:build e2e

package httpcatalog

// AllowPlaintextDatabases lets catalog database entries for Kubernetes
// Service hosts use sslmode disable. It exists only in binaries built with
// the e2e tag, which only the Kind test fixture image is.
func AllowPlaintextDatabases() { plaintextDatabases.Store(true) }

// The Kind fixture's database role is a plain "readonly", with no
// environment in its name.
func init() { rolesWithoutEnvironment = true }

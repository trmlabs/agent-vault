package pgproxy

import "errors"

var (
	// errCancelRequest is returned when the agent opens a Postgres CancelRequest
	// rather than a normal startup. The broker routes it using its session capability.
	errCancelRequest = errors.New("pgproxy: cancel request")
	// errMissingToken is returned when the agent presents an empty password. The
	// Agent Vault token is required to establish the vault scope.
	errMissingToken = errors.New("pgproxy: missing agent token")
)

package pgproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// readStartup reads the agent's startup packet, transparently declining SSL and
// GSS encryption requests (the agent reaches this listener over loopback, so the
// broker↔agent hop needs no TLS). A CancelRequest is surfaced as
// errCancelRequest so the caller can route it without a password handshake.
func readStartup(backend *pgproto3.Backend, conn net.Conn) (*pgproto3.StartupMessage, error) {
	for {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, fmt.Errorf("receive startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, nil
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("decline ssl: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("decline gss: %w", err)
			}
		case *pgproto3.CancelRequest:
			return nil, &cancelRequestError{request: m}
		default:
			return nil, fmt.Errorf("unexpected startup message %T", msg)
		}
	}
}

// authenticateAgent requests the agent's Agent Vault token via a cleartext
// password prompt and validates it. The token identifies the agent and its
// vault scope; it is never a database credential. Returns the authorized scope
// or an error (the caller maps errors to a generic client-facing message so no
// internal detail leaks).
func authenticateAgent(ctx context.Context, backend *pgproto3.Backend, auth AgentAuthenticator, startup *pgproto3.StartupMessage) (*AgentScope, string, error) {
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return nil, "", fmt.Errorf("request agent token: %w", err)
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return nil, "", err
	}

	msg, err := backend.Receive()
	if err != nil {
		return nil, "", fmt.Errorf("receive agent token: %w", err)
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return nil, "", fmt.Errorf("expected password message, got %T", msg)
	}
	if pw.Password == "" {
		return nil, "", errMissingToken
	}

	// An optional startup parameter lets an instance-scoped token name its vault,
	// mirroring the HTTP path's vault hint. A vault-scoped session token needs no
	// hint.
	scope, err := auth.Authenticate(ctx, pw.Password, startup.Parameters["agent_vault_vault"])
	if err != nil {
		return nil, "", fmt.Errorf("authenticate agent token: %w", err)
	}
	return scope, pw.Password, nil
}

// sendClientReady completes the agent-facing handshake by replaying the
// upstream's post-authentication state: AuthenticationOk, every upstream
// ParameterStatus, the BackendKeyData, and ReadyForQuery. After this the agent
// believes it is authenticated and issues queries over the already-established
// upstream session — without ever receiving a database credential.
func sendClientReady(backend *pgproto3.Backend, sess *upstreamSession) error {
	backend.Send(&pgproto3.AuthenticationOk{})
	for i := range sess.parameters {
		backend.Send(&sess.parameters[i])
	}
	if sess.backendKey != nil {
		backend.Send(sess.backendKey)
	}
	txStatus := sess.txStatus
	if txStatus == 0 {
		txStatus = 'I'
	}
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
	if err := backend.Flush(); err != nil {
		return fmt.Errorf("send ready to agent: %w", err)
	}
	return nil
}

// writeClientError sends a FATAL ErrorResponse to the agent before any raw
// relay begins, so a failed handshake surfaces as a clean Postgres error rather
// than a dropped connection. Messages are deliberately generic.
func writeClientError(backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: message})
	_ = backend.Flush()
}

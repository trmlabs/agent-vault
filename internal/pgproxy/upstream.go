package pgproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// upstreamSession is the result of authenticating to the upstream database: the
// live connection plus the post-authentication startup messages the proxy
// replays to the agent (parameter statuses, backend key data, initial tx
// status).
type upstreamSession struct {
	conn       net.Conn
	parameters []pgproto3.ParameterStatus
	backendKey *pgproto3.BackendKeyData
	txStatus   byte
}

// connectUpstream dials the upstream database and completes its authentication
// handshake with the Vault-issued username/password. clientParams are the
// agent's startup runtime parameters; a safe subset is forwarded so the
// upstream session mirrors what the agent asked for. On any failure the dialed
// connection is closed.
func connectUpstream(ctx context.Context, dial DialFunc, svc *DatabaseService, lease *Lease, clientParams map[string]string) (*upstreamSession, error) {
	rawConn, err := dial(ctx, "tcp", svc.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", svc.Addr, err)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopCancel()
	ok := false
	defer func() {
		if !ok {
			_ = rawConn.Close()
		}
	}()
	if deadline, has := ctx.Deadline(); has {
		_ = rawConn.SetDeadline(deadline)
	}

	// Negotiate upstream TLS per the service's sslmode. conn is the raw or the
	// TLS-wrapped connection; closing it closes the underlying socket. secure is
	// true only when the broker->database channel is encrypted.
	conn, secure, err := negotiateUpstreamTLS(ctx, rawConn, svc)
	if err != nil {
		return nil, err
	}

	frontend := pgproto3.NewFrontend(&messageReader{reader: conn}, conn)
	frontend.SetMaxBodyLen(maxAuthMessageBytes)

	database := svc.Database
	if database == "" {
		database = clientParams["database"]
	}
	params := map[string]string{"user": lease.Username}
	if database != "" {
		params["database"] = database
	}
	for key, value := range clientParams {
		if forwardableStartupParam(key) {
			params[key] = value
		}
	}

	frontend.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params})
	if err := frontend.Flush(); err != nil {
		return nil, fmt.Errorf("send upstream startup: %w", err)
	}
	if err := authenticateUpstream(frontend, lease, secure && sslMode(svc.SSLMode) == "verify-full"); err != nil {
		return nil, err
	}

	sess := &upstreamSession{conn: conn}
	if err := collectUpstreamReady(frontend, sess); err != nil {
		return nil, err
	}

	// The relay phase manages its own lifecycle; drop the handshake deadline.
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return sess, nil
}

// authenticateUpstream drives the upstream authentication request/response loop
// until AuthenticationOk. It supports the mechanisms a Vault-managed PostgreSQL
// role uses in practice: SCRAM-SHA-256 (the modern default) and cleartext
// password. Legacy md5 and GSSAPI are rejected with a clear error rather than
// silently downgrading.
func authenticateUpstream(frontend *pgproto3.Frontend, lease *Lease, verifiedTLS bool) error {
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return fmt.Errorf("upstream auth: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			return nil
		case *pgproto3.AuthenticationCleartextPassword:
			// Encryption alone does not authenticate the recipient. A MITM
			// with an arbitrary certificate must not obtain the Vault password.
			// SCRAM remains available for the explicitly weaker TLS modes.
			if !verifiedTLS {
				return fmt.Errorf("upstream requested cleartext password without verified TLS; use sslmode=verify-full")
			}
			frontend.Send(&pgproto3.PasswordMessage{Password: lease.Password})
			if err := frontend.Flush(); err != nil {
				return fmt.Errorf("send cleartext password: %w", err)
			}
		case *pgproto3.AuthenticationSASL:
			if err := authenticateUpstreamSASL(frontend, lease, m); err != nil {
				return err
			}
		case *pgproto3.AuthenticationMD5Password:
			return fmt.Errorf("upstream requires md5 authentication, which is not supported; use scram-sha-256")
		case *pgproto3.AuthenticationGSS, *pgproto3.AuthenticationGSSContinue:
			return fmt.Errorf("upstream requires GSSAPI authentication, which is not supported")
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream rejected authentication: %s (%s)", m.Message, m.Code)
		default:
			return fmt.Errorf("unexpected message during upstream auth: %T", msg)
		}
	}
}

// authenticateUpstreamSASL performs one SCRAM-SHA-256 SASL exchange, leaving the
// loop in authenticateUpstream to consume the trailing AuthenticationOk.
func authenticateUpstreamSASL(frontend *pgproto3.Frontend, lease *Lease, offer *pgproto3.AuthenticationSASL) error {
	if !slices.Contains(offer.AuthMechanisms, scramMechanism) {
		return fmt.Errorf("upstream offered SASL mechanisms %v; %s is required", offer.AuthMechanisms, scramMechanism)
	}
	client, err := newSCRAMClient(lease.Password)
	if err != nil {
		return err
	}

	frontend.Send(&pgproto3.SASLInitialResponse{AuthMechanism: scramMechanism, Data: []byte(client.firstMessage())})
	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASL initial response: %w", err)
	}

	cont, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("receive SASL continue: %w", err)
	}
	scont, ok := cont.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return unexpectedSASL("SASLContinue", cont)
	}
	final, err := client.finalMessage(string(scont.Data))
	if err != nil {
		return err
	}

	frontend.Send(&pgproto3.SASLResponse{Data: []byte(final)})
	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASL response: %w", err)
	}

	fin, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("receive SASL final: %w", err)
	}
	sfin, ok := fin.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		return unexpectedSASL("SASLFinal", fin)
	}
	return client.checkServerFinal(string(sfin.Data))
}

func unexpectedSASL(want string, got pgproto3.BackendMessage) error {
	if er, ok := got.(*pgproto3.ErrorResponse); ok {
		return fmt.Errorf("upstream rejected SASL: %s (%s)", er.Message, er.Code)
	}
	return fmt.Errorf("expected %s during upstream SASL, got %T", want, got)
}

// collectUpstreamReady reads the messages the upstream emits after
// authentication (ParameterStatus, BackendKeyData) up to ReadyForQuery, so the
// proxy can replay them to the agent and present an identical ready state.
func collectUpstreamReady(frontend *pgproto3.Frontend, sess *upstreamSession) error {
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return fmt.Errorf("upstream startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ParameterStatus:
			if len(sess.parameters) >= 128 {
				return fmt.Errorf("too many upstream startup parameters")
			}
			sess.parameters = append(sess.parameters, pgproto3.ParameterStatus{Name: m.Name, Value: m.Value})
		case *pgproto3.BackendKeyData:
			sess.backendKey = &pgproto3.BackendKeyData{ProcessID: m.ProcessID, SecretKey: append([]byte(nil), m.SecretKey...)}
		case *pgproto3.NoticeResponse:
			// Startup notices carry no session state; drop them.
		case *pgproto3.ReadyForQuery:
			sess.txStatus = m.TxStatus
			return nil
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream startup error: %s (%s)", m.Message, m.Code)
		default:
			return fmt.Errorf("unexpected message during upstream startup: %T", msg)
		}
	}
}

// sslMode normalizes a service's TLS mode string. An empty or unknown value
// defaults to "prefer".
func sslMode(mode string) string {
	switch mode {
	case "disable", "prefer", "require", "verify-full":
		return mode
	default:
		return "prefer"
	}
}

// negotiateUpstreamTLS performs the PostgreSQL SSL negotiation according to the
// service's sslmode and returns the connection to use (raw or TLS-wrapped) and
// whether the channel is encrypted:
//   - disable: no negotiation; plaintext.
//   - prefer (default): request TLS, use it if offered, else plaintext.
//   - require: request TLS, fail if the server declines; encrypt without
//     verifying the certificate (matching libpq).
//   - verify-full: as require, but verify the certificate chain and hostname.
func negotiateUpstreamTLS(ctx context.Context, conn net.Conn, svc *DatabaseService) (net.Conn, bool, error) {
	switch svc.SSLMode {
	case "", "disable", "prefer", "require", "verify-full":
	default:
		return nil, false, fmt.Errorf("invalid upstream sslmode")
	}
	mode := sslMode(svc.SSLMode)
	if mode == "disable" {
		return conn, false, nil
	}
	// SSLRequest: 4-byte length (8) + the 80877103 request code.
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return nil, false, fmt.Errorf("send SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, false, fmt.Errorf("read SSLRequest response: %w", err)
	}
	if resp[0] != 'S' && resp[0] != 'N' {
		return nil, false, fmt.Errorf("invalid upstream SSL response")
	}
	if resp[0] != 'S' {
		if mode == "require" || mode == "verify-full" {
			return nil, false, fmt.Errorf("upstream does not support TLS but sslmode=%s requires it", mode)
		}
		return conn, false, nil // prefer: fall back to plaintext
	}

	host, _, err := net.SplitHostPort(svc.Addr)
	if err != nil {
		host = svc.Addr
	}
	tlsConf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if mode != "verify-full" {
		// require encrypts without certificate verification, matching libpq's
		// sslmode=require. verify-full performs full chain + hostname verification.
		tlsConf.InsecureSkipVerify = true //nolint:gosec // intentional per sslmode=require
	}
	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, false, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return tlsConn, true, nil
}

// forwardableStartupParam reports whether an agent-supplied startup parameter is
// safe to forward to the upstream. user/database are set from the resolved
// service and Vault credential; only well-known single-value client runtime
// GUCs are passed through. "options" is deliberately excluded: PostgreSQL
// interprets it as backend command-line arguments, letting the agent set
// arbitrary session GUCs the operator's Vault role may have meant to fix.
func forwardableStartupParam(key string) bool {
	switch key {
	case "application_name",
		"client_encoding",
		"DateStyle",
		"TimeZone",
		"extra_float_digits",
		"search_path",
		"standard_conforming_strings":
		return true
	default:
		return false
	}
}

package pgproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// --- test doubles for the three broker dependencies ---

type fakeAuth struct {
	scope    *AgentScope
	err      error
	mu       sync.Mutex
	gotToken string
}

func (f *fakeAuth) Authenticate(_ context.Context, token, _ string) (*AgentScope, error) {
	f.mu.Lock()
	f.gotToken = token
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.scope, nil
}

type fakeResolver struct {
	svc *DatabaseService
	err error
}

func (f *fakeResolver) ResolveDatabase(_ context.Context, _ AgentScope, _ string) (*DatabaseService, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.svc, nil
}

type fakeMinter struct {
	lease   *Lease
	mintErr error

	mu         sync.Mutex
	mintCalls  int
	renewCalls int
	revoked    []string
}

func (f *fakeMinter) Mint(_ context.Context, _ string, _ *DatabaseService) (*Lease, error) {
	f.mu.Lock()
	f.mintCalls++
	f.mu.Unlock()
	if f.mintErr != nil {
		return nil, f.mintErr
	}
	return f.lease, nil
}

func (f *fakeMinter) Renew(_ context.Context, _ string, _ time.Duration) (time.Time, error) {
	f.mu.Lock()
	f.renewCalls++
	f.mu.Unlock()
	return time.Now().Add(time.Hour), nil
}

func (f *fakeMinter) Revoke(_ context.Context, leaseID string) error {
	f.mu.Lock()
	f.revoked = append(f.revoked, leaseID)
	f.mu.Unlock()
	return nil
}

func (f *fakeMinter) revokedLeases() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func (f *fakeMinter) mintCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mintCalls
}

// --- fake upstream PostgreSQL server ---

type upstreamAuthMode int

const (
	authTrust upstreamAuthMode = iota
	authCleartext
	authSCRAM
)

type fakeUpstream struct {
	ln        net.Listener
	authMode  upstreamAuthMode
	password  string
	tlsConfig *tls.Config // when set, the fake offers TLS in response to SSLRequest

	mu          sync.Mutex
	lastUser    string
	lastDB      string
	lastAppNm   string
	forbidParam string // a param key that must never be forwarded upstream
	forbidSeen  bool
}

func startFakeUpstream(t *testing.T, mode upstreamAuthMode, password string) *fakeUpstream {
	t.Helper()
	return startFakeUpstreamTLS(t, mode, password, nil)
}

func startFakeUpstreamTLS(t *testing.T, mode upstreamAuthMode, password string, tlsConfig *tls.Config) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fu := &fakeUpstream{ln: ln, authMode: mode, password: password, tlsConfig: tlsConfig}
	go fu.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return fu
}

// selfSignedTLSConfig builds a throwaway server TLS config for the fake upstream.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
}

func (fu *fakeUpstream) addr() string { return fu.ln.Addr().String() }

func (fu *fakeUpstream) seenUser() string {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	return fu.lastUser
}

func (fu *fakeUpstream) acceptLoop() {
	for {
		conn, err := fu.ln.Accept()
		if err != nil {
			return
		}
		go fu.handle(conn)
	}
}

func (fu *fakeUpstream) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	be := pgproto3.NewBackend(conn, conn)

	msg, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.SSLRequest); ok {
		if fu.tlsConfig != nil {
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tlsConn := tls.Server(conn, fu.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			be = pgproto3.NewBackend(conn, conn)
		} else if _, err := conn.Write([]byte{'N'}); err != nil {
			return
		}
		if msg, err = be.ReceiveStartupMessage(); err != nil {
			return
		}
	}
	startup, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	fu.mu.Lock()
	fu.lastUser = startup.Parameters["user"]
	fu.lastDB = startup.Parameters["database"]
	fu.lastAppNm = startup.Parameters["application_name"]
	if fu.forbidParam != "" {
		if _, seen := startup.Parameters[fu.forbidParam]; seen {
			fu.forbidSeen = true
		}
	}
	fu.mu.Unlock()

	switch fu.authMode {
	case authTrust:
		be.Send(&pgproto3.AuthenticationOk{})
	case authCleartext:
		be.Send(&pgproto3.AuthenticationCleartextPassword{})
		if err := be.Flush(); err != nil {
			return
		}
		_ = be.SetAuthType(pgproto3.AuthTypeCleartextPassword)
		pm, err := be.Receive()
		if err != nil {
			return
		}
		if pw, ok := pm.(*pgproto3.PasswordMessage); !ok || pw.Password != fu.password {
			sendFatal(be, "28P01", "bad password")
			return
		}
		be.Send(&pgproto3.AuthenticationOk{})
	case authSCRAM:
		if err := fu.scramServer(be); err != nil {
			sendFatal(be, "28P01", "scram failed: "+err.Error())
			return
		}
		be.Send(&pgproto3.AuthenticationOk{})
	}

	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0 (fake)"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{9, 8, 7, 6}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	for {
		m, err := be.Receive()
		if err != nil {
			return
		}
		switch m.(type) {
		case *pgproto3.Query:
			// Answer any query with a single row echoing the authenticated user,
			// so the test can prove the upstream saw the Vault username.
			be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("current_user"), DataTypeOID: 25, Format: 0}}})
			be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(fu.seenUser())}})
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func sendFatal(be *pgproto3.Backend, code, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = be.Flush()
}

// scramServer implements the server half of SCRAM-SHA-256, validating the
// proxy's client proof independently of the proxy's own SCRAM code.
func (fu *fakeUpstream) scramServer(be *pgproto3.Backend) error {
	be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{scramMechanism}})
	if err := be.Flush(); err != nil {
		return err
	}
	_ = be.SetAuthType(pgproto3.AuthTypeSASL)
	m, err := be.Receive()
	if err != nil {
		return err
	}
	init, ok := m.(*pgproto3.SASLInitialResponse)
	if !ok {
		return fmt.Errorf("expected SASLInitialResponse, got %T", m)
	}
	clientFirst := string(init.Data)
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce, err := scramField(clientFirstBare, "r=")
	if err != nil {
		return err
	}

	nonceTail := make([]byte, 12)
	if _, err := rand.Read(nonceTail); err != nil {
		return err
	}
	combinedNonce := clientNonce + base64.StdEncoding.EncodeToString(nonceTail)
	salt := []byte("sixteen-byte-slt")
	const iters = 4096
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", combinedNonce, base64.StdEncoding.EncodeToString(salt), iters)

	be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := be.Flush(); err != nil {
		return err
	}
	_ = be.SetAuthType(pgproto3.AuthTypeSASLContinue)
	m2, err := be.Receive()
	if err != nil {
		return err
	}
	resp, ok := m2.(*pgproto3.SASLResponse)
	if !ok {
		return fmt.Errorf("expected SASLResponse, got %T", m2)
	}
	clientFinal := string(resp.Data)
	proofB64, err := scramField(clientFinal, "p=")
	if err != nil {
		return err
	}
	finalWithoutProof, _, found := strings.Cut(clientFinal, ",p=")
	if !found {
		return fmt.Errorf("client-final missing proof")
	}

	salted, err := pbkdf2.Key(sha256.New, fu.password, salt, iters, sha256.Size)
	if err != nil {
		return err
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	authMessage := clientFirstBare + "," + serverFirst + "," + finalWithoutProof
	clientSig := hmacSHA256(storedKey[:], []byte(authMessage))
	expectedProof := make([]byte, len(clientKey))
	for i := range clientKey {
		expectedProof[i] = clientKey[i] ^ clientSig[i]
	}
	gotProof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotProof, expectedProof) {
		return fmt.Errorf("client proof mismatch")
	}

	serverKey := hmacSHA256(salted, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(authMessage))
	be.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte("v=" + base64.StdEncoding.EncodeToString(serverSig))})
	return be.Flush()
}

func scramField(msg, prefix string) (string, error) {
	for _, part := range strings.Split(msg, ",") {
		if strings.HasPrefix(part, prefix) {
			return part[len(prefix):], nil
		}
	}
	return "", fmt.Errorf("scram field %q not found", prefix)
}

// --- fake agent client ---

// runAgentQuery drives an agent connection through the broker: startup with the
// given token as the password, then a single query, returning the first cell of
// the first row.
func runAgentQuery(t *testing.T, brokerAddr, token, database, query string) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", brokerAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{
		"user":             "agent",
		"database":         database,
		"application_name": "agent-under-test",
	}})
	if err := fe.Flush(); err != nil {
		return "", err
	}

	// Authentication phase.
	for {
		msg, err := fe.Receive()
		if err != nil {
			return "", err
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			goto ready
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: token})
			if err := fe.Flush(); err != nil {
				return "", err
			}
		case *pgproto3.ErrorResponse:
			return "", fmt.Errorf("auth error: %s (%s)", m.Message, m.Code)
		default:
			return "", fmt.Errorf("unexpected message during agent auth: %T", msg)
		}
	}
ready:
	for {
		msg, err := fe.Receive()
		if err != nil {
			return "", err
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			return "", fmt.Errorf("startup error: %s (%s)", er.Message, er.Code)
		}
	}

	fe.Send(&pgproto3.Query{String: query})
	if err := fe.Flush(); err != nil {
		return "", err
	}
	var cell string
	for {
		msg, err := fe.Receive()
		if err != nil {
			return "", err
		}
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			if len(m.Values) > 0 {
				cell = string(m.Values[0])
			}
		case *pgproto3.ReadyForQuery:
			fe.Send(&pgproto3.Terminate{})
			_ = fe.Flush()
			return cell, nil
		case *pgproto3.ErrorResponse:
			return "", fmt.Errorf("query error: %s (%s)", m.Message, m.Code)
		}
	}
}

// --- harness ---

func startBroker(t *testing.T, opts Options) (*Broker, string) {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := New(ln.Addr().String(), opts)
	go func() { _ = b.Serve(ln) }()
	t.Cleanup(func() { _ = b.Shutdown(context.Background()) })
	return b, ln.Addr().String()
}

func newLease() *Lease {
	return &Lease{ID: "database/creds/readonly/lease-1", Username: "v-token-readonly-abc123", Password: "vault-minted-pw", ExpiresAt: time.Now().Add(time.Hour), Renewable: true}
}

func endToEndTest(t *testing.T, mode upstreamAuthMode) {
	t.Helper()
	lease := newLease()
	upstream := startFakeUpstream(t, mode, lease.Password)
	minter := &fakeMinter{lease: lease}
	auth := &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-7"}}
	_, addr := startBroker(t, Options{
		Auth:      auth,
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    minter,
	})

	got, err := runAgentQuery(t, addr, "agent-vault-token-xyz", "appdb", "SELECT current_user")
	if err != nil {
		t.Fatalf("agent query: %v", err)
	}
	if got != lease.Username {
		t.Fatalf("upstream saw user %q, want the Vault-minted %q", got, lease.Username)
	}
	if auth.gotToken != "agent-vault-token-xyz" {
		t.Errorf("authenticator got token %q", auth.gotToken)
	}
	if upstream.lastDB != "appdb" {
		t.Errorf("upstream database = %q, want appdb", upstream.lastDB)
	}
	if upstream.lastAppNm != "agent-under-test" {
		t.Errorf("upstream application_name = %q, want it forwarded", upstream.lastAppNm)
	}
	if minter.mintCalls != 1 {
		t.Errorf("mint calls = %d, want 1", minter.mintCalls)
	}
	// The lease must be revoked once the agent disconnects.
	waitFor(t, 2*time.Second, func() bool {
		revoked := minter.revokedLeases()
		return len(revoked) == 1 && revoked[0] == lease.ID
	}, "lease was not revoked on disconnect")
}

func TestBroker_EndToEnd_TrustUpstream(t *testing.T) { endToEndTest(t, authTrust) }
func TestBroker_EndToEnd_SCRAMUpstream(t *testing.T) { endToEndTest(t, authSCRAM) }

func TestBroker_AgentAuthFailure(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{err: fmt.Errorf("invalid token")},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "x", Addr: upstream.addr()}},
		Leases:    minter,
	})

	if _, err := runAgentQuery(t, addr, "bad-token", "appdb", "SELECT 1"); err == nil {
		t.Fatal("expected the agent to receive an auth error")
	}
	if minter.mintCalls != 0 {
		t.Errorf("mint must not be called when the agent fails auth; got %d calls", minter.mintCalls)
	}
}

func TestBroker_MintFailure_NoRevoke(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	minter := &fakeMinter{mintErr: fmt.Errorf("vault unreachable")}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "x", Addr: upstream.addr()}},
		Leases:    minter,
	})

	if _, err := runAgentQuery(t, addr, "tok", "appdb", "SELECT 1"); err == nil {
		t.Fatal("expected an error when credential minting fails")
	}
	if got := minter.revokedLeases(); len(got) != 0 {
		t.Errorf("nothing was minted, so nothing should be revoked; got %v", got)
	}
}

func TestBroker_ResolveFailure(t *testing.T) {
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1"}},
		Databases: &fakeResolver{err: fmt.Errorf("no such service")},
		Leases:    minter,
	})
	if _, err := runAgentQuery(t, addr, "tok", "unknowndb", "SELECT 1"); err == nil {
		t.Fatal("expected an error when the database service cannot be resolved")
	}
	if minter.mintCalls != 0 {
		t.Errorf("mint must not run when resolution fails; got %d", minter.mintCalls)
	}
}

func TestBroker_ShutdownIsListening(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, "")
	b, _ := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "v1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "x", Addr: upstream.addr()}},
		Leases:    &fakeMinter{lease: newLease()},
	})
	waitFor(t, time.Second, b.IsListening, "broker never started listening")
	if err := b.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	waitFor(t, time.Second, func() bool { return !b.IsListening() }, "broker still listening after shutdown")
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

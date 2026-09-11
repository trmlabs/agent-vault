package pgproxy

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestSCRAMClient_RFC7677Vector pins the SCRAM-SHA-256 computation to the
// worked example in RFC 7677 (username "user", password "pencil"). The client
// nonce and server-first message are fixed, so the client proof and the server
// signature are deterministic and must match the RFC byte-for-byte.
func TestSCRAMClient_RFC7677Vector(t *testing.T) {
	s := &scramClient{password: "pencil", clientNonce: "rOprNGfwEbeRWgbNEkqO"}
	// The RFC exchange uses "n=user"; Postgres ignores the field but the proof is
	// computed over whatever the client actually sent, so match it here.
	s.firstBare = "n=user,r=rOprNGfwEbeRWgbNEkqO"

	serverFirst := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	final, err := s.finalMessage(serverFirst)
	if err != nil {
		t.Fatalf("finalMessage: %v", err)
	}
	wantFinal := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	if final != wantFinal {
		t.Fatalf("client-final mismatch:\n got %q\nwant %q", final, wantFinal)
	}
	if err := s.checkServerFinal("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="); err != nil {
		t.Fatalf("checkServerFinal on the RFC verifier: %v", err)
	}
}

// TestSCRAMClient_RoundTrip runs a full exchange against an in-test server that
// knows the password, exercising the random-nonce path of newSCRAMClient.
func TestSCRAMClient_RoundTrip(t *testing.T) {
	const password = "s3cr3t-Vault-Pw"
	client, err := newSCRAMClient(password)
	if err != nil {
		t.Fatalf("newSCRAMClient: %v", err)
	}

	first := client.firstMessage()
	if !strings.HasPrefix(first, "n,,n=,r=") {
		t.Fatalf("client-first has unexpected shape: %q", first)
	}
	clientNonce := strings.TrimPrefix(first, "n,,n=,r=")

	// Server side: fixed salt/iterations, extend the nonce, compute the verifier.
	salt := []byte("0123456789abcdef")
	const iters = 4096
	serverNonce := clientNonce + "SERVERPART"
	serverFirst := "r=" + serverNonce + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"

	final, err := client.finalMessage(serverFirst)
	if err != nil {
		t.Fatalf("finalMessage: %v", err)
	}
	if !strings.Contains(final, "r="+serverNonce) {
		t.Fatalf("client-final did not echo the combined nonce: %q", final)
	}

	// Independently derive the server signature and confirm the client accepts it.
	salted, err := pbkdf2.Key(sha256.New, password, salt, iters, sha256.Size)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	authMessage := client.firstBare + "," + serverFirst + ",c=biws,r=" + serverNonce
	serverKey := hmacSHA256(salted, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(authMessage))
	if err := client.checkServerFinal("v=" + base64.StdEncoding.EncodeToString(serverSig)); err != nil {
		t.Fatalf("checkServerFinal on a valid verifier: %v", err)
	}
}

func TestSCRAMClient_RejectsBadServer(t *testing.T) {
	// Server nonce that does not extend the client nonce must be rejected.
	s := &scramClient{password: "pencil", clientNonce: "abc"}
	s.firstBare = "n=,r=abc"
	if _, err := s.finalMessage("r=DIFFERENT,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"); err == nil {
		t.Fatal("expected rejection when server nonce does not extend the client nonce")
	}

	// Valid proof computation, then a tampered server signature must be rejected.
	s2 := &scramClient{password: "pencil", clientNonce: "abc"}
	s2.firstBare = "n=,r=abc"
	if _, err := s2.finalMessage("r=abcXYZ,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"); err != nil {
		t.Fatalf("finalMessage: %v", err)
	}
	if err := s2.checkServerFinal("v=" + base64.StdEncoding.EncodeToString([]byte("not-the-right-signature-32bytes!"))); err == nil {
		t.Fatal("expected rejection of a tampered server signature")
	}
	if err := s2.checkServerFinal("e=other-error"); err == nil {
		t.Fatal("expected error when server reports a SCRAM error")
	}
}

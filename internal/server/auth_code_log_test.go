package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = original }()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestPasswordResetCodeNeverLogged(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "old-password-123")
	srv := newTestServer(withStore(ms))
	logged := captureStderr(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{"email":"owner@test.com"}`))
		srv.httpServer.Handler.ServeHTTP(httptest.NewRecorder(), req)
	})
	if len(ms.passwordResets) != 1 {
		t.Fatalf("expected 1 password reset, got %d", len(ms.passwordResets))
	}
	if strings.Contains(logged, ms.passwordResets[0].Code) {
		t.Fatal("password reset code written to stderr")
	}
	if !strings.Contains(logged, "not delivered") {
		t.Fatalf("expected an undelivered notice, got %q", logged)
	}
}

func TestEmailVerificationCodeNeverLogged(t *testing.T) {
	ms := setupMockStoreWithInactiveUser(t, "new@test.com", "password123")
	srv := newTestServer(withStore(ms))
	logged := captureStderr(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(`{"email":"new@test.com"}`))
		srv.httpServer.Handler.ServeHTTP(httptest.NewRecorder(), req)
	})
	if len(ms.emailVerifications) != 1 {
		t.Fatalf("expected 1 email verification, got %d", len(ms.emailVerifications))
	}
	if strings.Contains(logged, ms.emailVerifications[0].Code) {
		t.Fatal("email verification code written to stderr")
	}
}

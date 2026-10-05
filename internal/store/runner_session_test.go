package store

import (
	"context"
	"testing"
	"time"
)

func TestRunnerSessionPins(t *testing.T) { checkRunnerSessionPins(t, openTestDB(t)) }

func checkRunnerSessionPins(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	hour := time.Now().Add(time.Hour)
	if pod, err := s.BindRunnerSession(ctx, "tok-1", "pod-a", hour); err != nil || pod != "pod-a" {
		t.Fatalf("first pin: %q %v", pod, err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-1", "pod-b", hour); err != nil || pod != "pod-a" {
		t.Fatalf("second Pod got %q %v, want the first Pod", pod, err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-2", "pod-b", hour); err != nil || pod != "pod-b" {
		t.Fatalf("another token: %q %v", pod, err)
	}
	// An expired pin frees the token hash (the token itself is expired too).
	if _, err := s.BindRunnerSession(ctx, "tok-3", "pod-a", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-3", "pod-b", hour); err != nil || pod != "pod-b" {
		t.Fatalf("expired pin still held: %q %v", pod, err)
	}
	if _, err := s.BindRunnerSession(ctx, "", "pod-a", hour); err == nil {
		t.Fatal("empty token pinned")
	}
}

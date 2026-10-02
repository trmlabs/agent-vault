package server

import (
	"testing"
	"time"
)

func TestShutdownBudgetDefaultsToFiveSeconds(t *testing.T) {
	s := &Server{}
	if got := s.shutdownBudget(); got != 5*time.Second {
		t.Fatalf("default shutdown budget = %v, want 5s", got)
	}
	s.SetShutdownTimeout(30 * time.Second)
	if got := s.shutdownBudget(); got != 30*time.Second {
		t.Fatalf("set shutdown budget = %v, want 30s", got)
	}
}

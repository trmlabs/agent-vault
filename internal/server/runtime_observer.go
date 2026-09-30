package server

import (
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

// EnableCleanupObserver is startup-only and opt-in. It accepts no owner session
// or proxy permission as observer authority. The existing loopback management
// listener must remain behind verified, restricted transport.
func (s *Server) EnableCleanupObserver(authorize runtimestatus.Authorize) error {
	if !s.credentialProxy || s.pgBroker == nil {
		return fmt.Errorf("cleanup observer requires strict database broker")
	}
	minter, ok := s.pgLeaseCloser.(*pgproxy.DurableLeaseMinter)
	if !ok {
		return fmt.Errorf("cleanup observer requires durable database cleanup")
	}
	handler, err := runtimestatus.New(authorize, pgproxy.CleanupSnapshot(s.pgBroker, minter))
	if err != nil {
		return err
	}
	s.cleanupObserver = handler
	return nil
}

func (s *Server) handleCleanupObserver(w http.ResponseWriter, r *http.Request) {
	if s.cleanupObserver == nil {
		http.NotFound(w, r)
		return
	}
	s.cleanupObserver.ServeHTTP(w, r)
}

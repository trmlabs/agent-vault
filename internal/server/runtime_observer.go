package server

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

// EnableCleanupObserver is startup-only and opt-in. It accepts no owner session
// or proxy permission as observer authority. A separate loopback-only listener
// contains no management routes and requires verified, restricted TLS transport.
func (s *Server) EnableCleanupObserver(authorize runtimestatus.Authorize, port int) error {
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
	listener, err := cleanupObserverHTTPServer(handler, port)
	if err != nil {
		return err
	}
	s.cleanupObserverServer = listener
	return nil
}

func cleanupObserverHTTPServer(handler http.Handler, port int) (*http.Server, error) {
	if handler == nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("cleanup observer requires a numeric port from 1 through 65535")
	}
	return &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 15 * time.Second, MaxHeaderBytes: 40960}, nil
}

func (s *Server) listenCleanupObserver() (net.Listener, error) {
	if s.cleanupObserverServer == nil {
		return nil, nil
	}
	ln, err := net.Listen("tcp4", s.cleanupObserverServer.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen cleanup observer: %w", err)
	}
	return ln, nil
}

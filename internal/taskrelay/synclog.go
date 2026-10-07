package taskrelay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

// Why a Pod cache sync failed, by class only: never a token, a response
// body or a header. A sync that keeps failing is otherwise silent until the
// shared proxy gives up on its first sync and exits.
const (
	syncFailToken   = "token"   // the API token file is unreadable or empty
	syncFailDNS     = "dns"     // the API server's name did not resolve
	syncFailTimeout = "timeout" // no answer in time (often DNS or egress blocked)
	syncFailConnect = "connect" // the connection was refused or unreachable
	syncFailTLS     = "tls"     // the API server's certificate did not verify
	syncFailHTTP    = "http"    // the API server answered with a non-200 status
	syncFailOther   = "other"   // a request, read or decode failure
)

// syncLogInterval spaces repeat lines for a namespace whose sync keeps
// failing the same way; a change of class is logged at once.
var syncLogInterval = time.Minute

// syncError is a failed Pod cache request: its class and, for an HTTP
// answer, the status. It is errDenied to every caller.
type syncError struct {
	class  string
	status int
	host   string // the name that did not resolve (dns only)
}

func (e *syncError) Error() string { return errDenied.Error() }
func (e *syncError) Unwrap() error { return errDenied }

// classifyTransport names a transport failure without its message.
func classifyTransport(e error) *syncError {
	var dns *net.DNSError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var timeout interface{ Timeout() bool }
	var op *net.OpError
	switch {
	case errors.As(e, &dns):
		return &syncError{class: syncFailDNS, host: dns.Name}
	case errors.As(e, &unknown), errors.As(e, &hostname), errors.As(e, &invalid), errors.As(e, &verify), errors.As(e, &record):
		return &syncError{class: syncFailTLS}
	case errors.Is(e, context.DeadlineExceeded), errors.As(e, &timeout) && timeout.Timeout():
		return &syncError{class: syncFailTimeout}
	case errors.As(e, &op):
		return &syncError{class: syncFailConnect}
	}
	return &syncError{class: syncFailOther}
}

// syncWatch logs each namespace's failed syncs: the first, any change of
// class or status, then at most one line per syncLogInterval with the count
// since; and one line when a sync succeeds again.
type syncWatch struct {
	mu    sync.Mutex
	state map[string]*syncState
}

type syncState struct {
	class, status string
	logged        time.Time
	since         time.Time
	failures      int
	unlogged      int
}

func (w *syncWatch) failed(log *slog.Logger, namespace string, e error, now time.Time) {
	var s *syncError
	if !errors.As(e, &s) {
		s = &syncError{class: syncFailOther}
	}
	status := ""
	if s.status != 0 {
		status = strconv.Itoa(s.status)
	}
	w.mu.Lock()
	if w.state == nil {
		w.state = map[string]*syncState{}
	}
	st := w.state[namespace]
	if st == nil {
		st = &syncState{since: now}
		w.state[namespace] = st
	}
	st.failures++
	changed := st.class != s.class || st.status != status
	due := now.Sub(st.logged) >= syncLogInterval
	if !changed && !due {
		st.unlogged++
		w.mu.Unlock()
		return
	}
	suppressed := st.unlogged
	st.class, st.status, st.logged, st.unlogged = s.class, status, now, 0
	failures := st.failures
	w.mu.Unlock()
	attrs := []any{"namespace", namespace, "class", s.class, "failures", failures, "suppressed", suppressed}
	if s.status != 0 {
		attrs = append(attrs, "status", s.status)
	}
	if s.host != "" {
		attrs = append(attrs, "host", s.host)
	}
	log.Warn("pod_cache_sync_failed", attrs...)
}

func (w *syncWatch) synced(log *slog.Logger, namespace string, now time.Time) {
	w.mu.Lock()
	st := w.state[namespace]
	delete(w.state, namespace)
	w.mu.Unlock()
	if st != nil {
		log.Info("pod_cache_sync_restored", "namespace", namespace, "failures", st.failures,
			"downMs", now.Sub(st.since).Milliseconds())
	}
}

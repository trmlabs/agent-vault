package taskrelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// logOutput receives the relay's structured log: JSON lines on stderr, apart
// from the audit trail (which may be stdout in shared mode). Tests swap it.
var logOutput io.Writer = os.Stderr

func newRelayLog() *slog.Logger {
	return slog.New(slog.NewJSONHandler(logOutput, nil)).With("component", "gatehouse-relay")
}

// Why a relayed session ended. The first cause recorded wins: a later error
// on the other side is the consequence, not the cause.
const (
	endClientClosed   = "client_closed"   // the agent closed its side
	endClientReset    = "client_reset"    // the agent's side failed
	endUpstreamClosed = "upstream_closed" // the broker side closed cleanly
	endUpstreamReset  = "upstream_reset"  // the broker side failed: reset, truncated TLS, a dead front
	endDeadline       = "deadline"        // the session's deadline passed
	endWithdrawn      = "agent_withdrawn" // the agent Pod stopped qualifying
	endRelayStopping  = "relay_stopping"  // the relay itself is stopping
)

// ending records why a session ended.
type ending struct {
	mu     sync.Mutex
	reason string
}

func (e *ending) set(reason string) {
	if reason == "" {
		return
	}
	e.mu.Lock()
	if e.reason == "" {
		e.reason = reason
	}
	e.mu.Unlock()
}

func (e *ending) get() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reason == "" {
		return "closed"
	}
	return e.reason
}

// readCause is the end reason a read error on one side means, or "" when the
// relay closed that side itself.
func readCause(upstream bool, e error) string {
	var timeout net.Error
	switch {
	case e == nil || errors.Is(e, net.ErrClosed):
		return ""
	case errors.As(e, &timeout) && timeout.Timeout():
		return endDeadline
	case errors.Is(e, io.EOF) && upstream:
		return endUpstreamClosed
	case errors.Is(e, io.EOF):
		return endClientClosed
	case upstream:
		return endUpstreamReset
	default:
		return endClientReset
	}
}

// watchedReader reports its first read error, as it happens.
type watchedReader struct {
	r    io.Reader
	once sync.Once
	on   func(error)
}

func (w *watchedReader) Read(p []byte) (int, error) {
	n, e := w.r.Read(p)
	if e != nil {
		w.once.Do(func() { w.on(e) })
	}
	return n, e
}

func watch(r io.Reader, upstream bool, end *ending) io.Reader {
	return &watchedReader{r: r, on: func(e error) { end.set(readCause(upstream, e)) }}
}

// stopCause is the end reason for a relay context that is done.
func stopCause(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return endDeadline
	}
	return endRelayStopping
}

// logClose writes one line per ended session: INFO for a normal end, WARN
// when the broker side failed. The upstream watch also counts broker-side
// ends, so a front that disappears is named once.
func (r *relay) logClose(protocol, peer string, agent agentIdentity, upstream, target string, started time.Time, end *ending) {
	reason := end.get()
	level := slog.LevelInfo
	if reason == endUpstreamReset {
		level = slog.LevelWarn
	}
	r.log.LogAttrs(context.Background(), level, "session_closed", slog.String("protocol", protocol), slog.String("reason", reason),
		slog.String("peer", peer), slog.String("pod", agent.pod), slog.String("target", target), slog.String("upstream", upstream),
		slog.Int64("durationMs", time.Since(started).Milliseconds()))
	if reason == endUpstreamReset || reason == endUpstreamClosed {
		r.upstreams.ended(r.log, upstream, reason)
	}
}

// massCloseWindow and massCloseMinimum: this many broker-side ends within the
// window are one event, an upstream that dropped its connections together
// (the broker's TLS front killed, say), logged once with the count.
const (
	massCloseWindow  = time.Second
	massCloseMinimum = 5
)

// upstreamWatch names an upstream's failures once instead of per connection.
type upstreamWatch struct {
	mu    sync.Mutex
	state map[string]*upstreamState
}

type upstreamState struct {
	down       bool
	downSince  time.Time
	windowEnds int
	resets     int
	windowOpen bool
}

func (w *upstreamWatch) get(address string) *upstreamState {
	if w.state == nil {
		w.state = map[string]*upstreamState{}
	}
	s := w.state[address]
	if s == nil {
		s = &upstreamState{}
		w.state[address] = s
	}
	return s
}

// ended counts one broker-side end; the first in a quiet spell opens a
// window, and at its close a burst is logged once.
func (w *upstreamWatch) ended(log *slog.Logger, address, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.get(address)
	s.windowEnds++
	if reason == endUpstreamReset {
		s.resets++
	}
	if s.windowOpen {
		return
	}
	s.windowOpen = true
	time.AfterFunc(massCloseWindow, func() {
		w.mu.Lock()
		ends, resets := s.windowEnds, s.resets
		s.windowEnds, s.resets, s.windowOpen = 0, 0, false
		w.mu.Unlock()
		if ends >= massCloseMinimum {
			log.Warn("upstream_dropped_sessions", "upstream", address, "sessions", ends, "resets", resets,
				"windowMs", massCloseWindow.Milliseconds())
		}
	})
}

// dialed records a dial's outcome: the first failure after success, and the
// first success after failure, are each logged once.
func (w *upstreamWatch) dialed(log *slog.Logger, address string, e error) {
	w.mu.Lock()
	s := w.get(address)
	wasDown, since := s.down, s.downSince
	if e != nil && !s.down {
		s.down, s.downSince = true, time.Now()
	}
	if e == nil {
		s.down = false
	}
	w.mu.Unlock()
	switch {
	case e != nil && !wasDown:
		log.Warn("upstream_unreachable", "upstream", address, "error", e.Error())
	case e == nil && wasDown:
		log.Info("upstream_restored", "upstream", address, "downMs", time.Since(since).Milliseconds())
	}
}

// refusalWatch names refused new connections without one line each: a limit
// refuses the new connection and never touches open ones, and the refusals in
// each window are logged once with their count.
type refusalWatch struct {
	mu      sync.Mutex
	count   int
	pending bool
}

func (w *refusalWatch) refused(log *slog.Logger, limit, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count++
	if w.pending {
		return
	}
	w.pending = true
	time.AfterFunc(massCloseWindow, func() {
		w.mu.Lock()
		n := w.count
		w.count, w.pending = 0, false
		w.mu.Unlock()
		log.Warn("connections_refused", "reason", reason, "limit", limit, "refused", n, "windowMs", massCloseWindow.Milliseconds())
	})
}

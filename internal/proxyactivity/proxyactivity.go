// Package proxyactivity keeps, in the broker's shared store, when each agent
// Sandbox was last in use through a shared proxy, so the idle janitor's view
// outlives any one proxy replica. Each replica reports its Sandboxes' last
// use and reads the whole view back for the janitor; both calls authenticate
// as the proxy itself, and a proxy reads and writes only its own binding's
// rows, for its own namespaces.
package proxyactivity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Store is the shared store's part this service uses.
type Store interface {
	RecordProxyActivity(ctx context.Context, scope string, rows []store.ProxyActivity, maxRows int, acked int64) (int64, bool, error)
	ReadProxyActivity(ctx context.Context, scope, after string, since time.Time, limit int) ([]store.ProxyActivity, error)
	ProxyActivityHistory(ctx context.Context, scope string) (time.Time, int64, bool, error)
	PruneProxyActivity(ctx context.Context, cutoff time.Time) error
}

// Identity is an admitted shared proxy: Scope names its binding, and
// Namespaces are the agent namespaces it serves.
type Identity struct {
	Scope      string
	Namespaces []string
}

// Identifier admits a shared proxy as itself and names its binding
// (workload identity's IdentifyProxy, adapted where the broker is wired).
type Identifier interface {
	IdentifyProxy(ctx context.Context, token string, peer netip.Addr) (Identity, error)
}

const (
	// RecordPath takes {"sandboxes": [{namespace, ownerUID, lastSeen}],
	// "ackedSeq"} and answers {"seq", "lost"}.
	RecordPath = "/v1/proxy/activity"
	// ReadPath takes {"after": cursor} and returns {"retentionSeconds",
	// "sandboxes", "next"}; an empty next is the last page.
	ReadPath = "/v1/proxy/activity/read"
	// MaxRecordRows bounds one report; a proxy sends more in several.
	MaxRecordRows = 5000
	// ReadPageRows is one read page.
	ReadPageRows   = 2000
	maxRecordBytes = 2 << 20
	pruneEvery     = time.Minute
)

// Row is one Sandbox's last use on the wire.
type Row struct {
	Namespace string    `json:"namespace"`
	OwnerUID  string    `json:"ownerUID"`
	LastSeen  time.Time `json:"lastSeen"`
}

// RecordRequest is a proxy's report.
type RecordRequest struct {
	Sandboxes []Row `json:"sandboxes"`
	// AckedSeq is the binding sequence last acknowledged to this replica, 0
	// for none (a replica that has not reported since it started).
	AckedSeq int64 `json:"ackedSeq"`
}

// RecordResponse acknowledges a report: Seq is the binding sequence it got.
// Lost says the broker's store no longer reaches AckedSeq: writes it
// acknowledged are gone (a restore to an earlier point), the binding's
// history has started again, and the replica should report everything it
// holds.
type RecordResponse struct {
	Seq  int64 `json:"seq"`
	Lost bool  `json:"lost"`
}

// ReadRequest asks for the page after a Sandbox UID.
type ReadRequest struct {
	After string `json:"after"`
}

// ReadResponse is one page of a binding's view. HistoryStarted is when the
// binding's history began (its first report), absent if it has none: the
// janitor deletes nothing until that is older than its idle window.
type ReadResponse struct {
	RetentionSeconds int64      `json:"retentionSeconds"`
	HistoryStarted   *time.Time `json:"historyStarted,omitempty"`
	// Seq is the binding's current sequence: a replica whose acknowledged
	// sequence is higher saw writes this store has lost.
	Seq       int64  `json:"seq"`
	Sandboxes []Row  `json:"sandboxes"`
	Next      string `json:"next"`
}

// Service serves both routes.
type Service struct {
	Store      Store
	Identifier Identifier
	// Retention is how long a row is kept after its last use.
	Retention time.Duration
	// MaxRows is the most rows one binding may hold (default
	// DefaultMaxRows), so a compromised proxy cannot grow the shared store
	// without bound. A report that would pass it is refused.
	MaxRows int
	Logger  *slog.Logger

	mu         sync.Mutex
	lastPruned time.Time
}

var ownerUID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// Validate checks the settings at startup.
func (s *Service) Validate() error {
	if s.Store == nil || s.Identifier == nil {
		return errors.New("proxy activity needs the shared store and workload identity")
	}
	if s.Retention < time.Hour || s.Retention > 366*24*time.Hour {
		return errors.New("proxy activity retention must be between one hour and a year")
	}
	if s.MaxRows < 0 || s.MaxRows > 100_000_000 {
		return errors.New("proxy activity maximum rows must be between 1 and 100,000,000")
	}
	return nil
}

// Register adds both routes to mux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+RecordPath, s.record)
	mux.HandleFunc("POST "+ReadPath, s.read)
}

// identify admits the caller as a proxy, or refuses it generically.
func (s *Service) identify(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, perr := netip.ParseAddr(host)
	if !ok || token == "" || err != nil || perr != nil {
		s.refuse(w, http.StatusUnauthorized, "no_token")
		return Identity{}, false
	}
	id, err := s.Identifier.IdentifyProxy(r.Context(), token, peer.Unmap())
	if err != nil || id.Scope == "" {
		s.refuse(w, http.StatusForbidden, "not_proxy")
		return id, false
	}
	return id, true
}

func (s *Service) record(w http.ResponseWriter, r *http.Request) {
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	var body RecordRequest
	d := json.NewDecoder(io.LimitReader(r.Body, maxRecordBytes))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || len(body.Sandboxes) > MaxRecordRows {
		s.refuse(w, http.StatusBadRequest, "body")
		return
	}
	now := time.Now()
	rows := make([]store.ProxyActivity, 0, len(body.Sandboxes))
	for _, row := range body.Sandboxes {
		// Only the proxy's own namespaces, and never a time ahead of the
		// broker's clock by more than a minute of skew.
		if !slices.Contains(id.Namespaces, row.Namespace) || !ownerUID.MatchString(row.OwnerUID) || row.LastSeen.IsZero() || row.LastSeen.After(now.Add(time.Minute)) {
			s.refuse(w, http.StatusBadRequest, "row")
			return
		}
		rows = append(rows, store.ProxyActivity{Namespace: row.Namespace, OwnerUID: row.OwnerUID, LastSeen: row.LastSeen})
	}
	if body.AckedSeq < 0 {
		s.refuse(w, http.StatusBadRequest, "body")
		return
	}
	seq, lost, err := s.Store.RecordProxyActivity(r.Context(), id.Scope, rows, s.maxRows(), body.AckedSeq)
	if errors.Is(err, store.ErrProxyActivityFull) {
		s.refuse(w, http.StatusInsufficientStorage, "row_ceiling")
		return
	} else if err != nil {
		s.refuse(w, http.StatusServiceUnavailable, "store")
		return
	}
	if lost {
		s.log().Warn("proxyactivity: the store lost acknowledged reports; history restarted", "scope", id.Scope, "acked", body.AckedSeq, "seq", seq)
	}
	s.prune(r.Context(), now)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RecordResponse{Seq: seq, Lost: lost})
}

func (s *Service) read(w http.ResponseWriter, r *http.Request) {
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	var body ReadRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || (body.After != "" && !ownerUID.MatchString(body.After)) {
		s.refuse(w, http.StatusBadRequest, "body")
		return
	}
	started, seq, known, err := s.Store.ProxyActivityHistory(r.Context(), id.Scope)
	if err != nil {
		s.refuse(w, http.StatusServiceUnavailable, "store")
		return
	}
	rows, err := s.Store.ReadProxyActivity(r.Context(), id.Scope, body.After, time.Now().Add(-s.Retention), ReadPageRows)
	if err != nil {
		s.refuse(w, http.StatusServiceUnavailable, "store")
		return
	}
	out := ReadResponse{RetentionSeconds: int64(s.Retention / time.Second), Seq: seq, Sandboxes: make([]Row, 0, len(rows))}
	if known {
		out.HistoryStarted = &started
	}
	for _, row := range rows {
		out.Sandboxes = append(out.Sandboxes, Row{Namespace: row.Namespace, OwnerUID: row.OwnerUID, LastSeen: row.LastSeen})
	}
	if len(rows) == ReadPageRows {
		out.Next = rows[len(rows)-1].OwnerUID
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// DefaultMaxRows sizes a binding's ceiling for a fleet of 10,000+ sandboxes
// with churn: ten times that many used within a day's retention.
const DefaultMaxRows = 100_000

func (s *Service) maxRows() int {
	if s.MaxRows == 0 {
		return DefaultMaxRows
	}
	return s.MaxRows
}

// prune drops expired rows at most once a minute per broker replica.
func (s *Service) prune(ctx context.Context, now time.Time) {
	s.mu.Lock()
	due := now.Sub(s.lastPruned) >= pruneEvery
	if due {
		s.lastPruned = now
	}
	s.mu.Unlock()
	if due {
		if err := s.Store.PruneProxyActivity(ctx, now.Add(-s.Retention)); err != nil {
			s.log().Warn("proxyactivity: prune failed", "error", err.Error())
		}
	}
}

func (s *Service) refuse(w http.ResponseWriter, status int, reason string) {
	s.log().Warn("proxyactivity: request refused", "reason", reason)
	http.Error(w, http.StatusText(status), status)
}

func (s *Service) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

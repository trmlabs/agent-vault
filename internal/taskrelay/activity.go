package taskrelay

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// activity records, for the idle janitor, when each agent Sandbox (the
// Pods' controller) was last in use through this replica: when one of its
// Pods started, when one was admitted, and every second while one of its
// connections stays open, so a long-lived tunnel or database session counts
// as use. It is keyed by the controller, so a replaced Pod keeps its
// Sandbox's history, and an entry is kept for the retention time after its
// last use whether or not the Pod is still running. It holds last-seen times
// only: no target, no bytes, no profile.
type activity struct {
	mu        sync.Mutex
	started   time.Time
	retention time.Duration
	owners    map[string]activityEntry // by controller UID
	// durable, when set, adds the broker's view of every replica.
	durable *durable
}

type activityEntry struct {
	namespace string
	lastSeen  time.Time
	pushed    time.Time // the last time the broker accepted for it
}

// defaultActivityRetention keeps a day of history, well past any idle time.
const defaultActivityRetention = 24 * time.Hour

func newActivity(now time.Time, retention time.Duration) *activity {
	return &activity{started: now, retention: retention, owners: map[string]activityEntry{}}
}

// seen records use by the agent att names at when; an earlier time than the
// one held changes nothing.
func (a *activity) seen(att workloadidentity.Attestation, when time.Time) {
	a.record(att.Namespace, att.OwnerUID, when)
}

func (a *activity) record(namespace, owner string, when time.Time) {
	if a == nil || owner == "" {
		return
	}
	a.mu.Lock()
	if e, ok := a.owners[owner]; !ok || when.After(e.lastSeen) {
		a.owners[owner] = activityEntry{namespace: namespace, lastSeen: when, pushed: e.pushed}
	}
	a.mu.Unlock()
}

// pending is every Sandbox whose last use is newer than the broker holds.
func (a *activity) pending() []SandboxActivity {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []SandboxActivity
	for owner, e := range a.owners {
		if e.lastSeen.After(e.pushed) {
			out = append(out, SandboxActivity{Namespace: e.namespace, OwnerUID: owner, LastSeen: e.lastSeen.UTC()})
		}
	}
	return out
}

// accepted marks rows the broker took.
func (a *activity) accepted(rows []SandboxActivity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range rows {
		if e, ok := a.owners[r.OwnerUID]; ok && r.LastSeen.After(e.pushed) {
			e.pushed = r.LastSeen
			a.owners[r.OwnerUID] = e
		}
	}
}

// ActivityReport is the admin listener's one response.
type ActivityReport struct {
	// ReplicaStarted is when this replica began recording. A Sandbox absent
	// from Sandboxes has not been used through this replica since then, or
	// not within RetentionSeconds.
	ReplicaStarted   time.Time         `json:"replicaStarted"`
	RetentionSeconds int64             `json:"retentionSeconds"`
	Sandboxes        []SandboxActivity `json:"sandboxes"`
	// Durable says Sandboxes include the broker's view of every replica,
	// read in full for this report, so no replica's going or coming loses
	// history beyond its last report to the broker.
	Durable bool `json:"durable"`
	// HistoryStarted, on a durable report, is when the broker's history for
	// this proxy's binding began. Zero means none yet: a new, recreated or
	// emptied history, which vouches for nothing.
	HistoryStarted time.Time `json:"historyStarted,omitzero"`
}

// SandboxActivity is one Sandbox's last use through this replica.
type SandboxActivity struct {
	Namespace string    `json:"namespace"`
	OwnerUID  string    `json:"ownerUID"`
	LastSeen  time.Time `json:"lastSeen"`
}

// report drops entries past the retention time and returns the rest.
func (a *activity) report(now time.Time) ActivityReport {
	a.mu.Lock()
	out := ActivityReport{ReplicaStarted: a.started.UTC(), RetentionSeconds: int64(a.retention / time.Second), Sandboxes: make([]SandboxActivity, 0, len(a.owners))}
	for owner, e := range a.owners {
		if now.Sub(e.lastSeen) > a.retention {
			delete(a.owners, owner)
			continue
		}
		out.Sandboxes = append(out.Sandboxes, SandboxActivity{Namespace: e.namespace, OwnerUID: owner, LastSeen: e.lastSeen.UTC()})
	}
	a.mu.Unlock()
	sort.Slice(out.Sandboxes, func(i, j int) bool { return out.Sandboxes[i].OwnerUID < out.Sandboxes[j].OwnerUID })
	return out
}

// ActivityPath is the admin listener's only route.
const ActivityPath = "/v1/activity"

// handler serves GET /v1/activity and nothing else: every other path and
// method is 404, so the admin port exposes last-seen times and no more.
func (a *activity) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != ActivityPath || req.URL.RawQuery != "" {
			http.NotFound(w, req)
			return
		}
		report := a.report(time.Now())
		if a.durable != nil {
			report = a.withDurable(req.Context(), report)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(report)
	})
}

// withDurable merges the broker's view into a report, keeping the later time
// per Sandbox and the shorter retention. If the view cannot be read in full,
// the report is this replica's alone and not durable.
func (a *activity) withDurable(ctx context.Context, report ActivityReport) ActivityReport {
	view, e := a.durable.read(ctx)
	if e != nil {
		return report
	}
	rows, retention := view.sandboxes, view.retention
	byOwner := make(map[string]int, len(report.Sandboxes))
	for i, s := range report.Sandboxes {
		byOwner[s.OwnerUID] = i
	}
	for _, r := range rows {
		if i, ok := byOwner[r.OwnerUID]; ok {
			if r.LastSeen.After(report.Sandboxes[i].LastSeen) {
				report.Sandboxes[i].LastSeen = r.LastSeen.UTC()
			}
			continue
		}
		byOwner[r.OwnerUID] = len(report.Sandboxes)
		report.Sandboxes = append(report.Sandboxes, SandboxActivity{Namespace: r.Namespace, OwnerUID: r.OwnerUID, LastSeen: r.LastSeen.UTC()})
	}
	sort.Slice(report.Sandboxes, func(i, j int) bool { return report.Sandboxes[i].OwnerUID < report.Sandboxes[j].OwnerUID })
	report.RetentionSeconds = min(report.RetentionSeconds, retention)
	report.Durable, report.HistoryStarted = true, view.historyStarted
	return report
}

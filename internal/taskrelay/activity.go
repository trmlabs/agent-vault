package taskrelay

import (
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
}

type activityEntry struct {
	namespace string
	lastSeen  time.Time
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
		a.owners[owner] = activityEntry{namespace: namespace, lastSeen: when}
	}
	a.mu.Unlock()
}

// ActivityReport is the admin listener's one response.
type ActivityReport struct {
	// ReplicaStarted is when this replica began recording. A Sandbox absent
	// from Sandboxes has not been used through this replica since then, or
	// not within RetentionSeconds.
	ReplicaStarted   time.Time         `json:"replicaStarted"`
	RetentionSeconds int64             `json:"retentionSeconds"`
	Sandboxes        []SandboxActivity `json:"sandboxes"`
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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(a.report(time.Now()))
	})
}

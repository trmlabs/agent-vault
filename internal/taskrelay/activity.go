package taskrelay

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// activity records, for the idle janitor, when each agent Pod last used this
// proxy replica: when it was admitted, and every second while one of its
// connections stays open, so a long-lived tunnel or database session counts
// as use. It holds last-seen times only: no target, no bytes, no profile.
type activity struct {
	mu      sync.Mutex
	started time.Time
	pods    map[string]activityEntry // by Pod UID
}

type activityEntry struct {
	namespace, owner string
	lastSeen         time.Time
}

func newActivity(now time.Time) *activity {
	return &activity{started: now, pods: map[string]activityEntry{}}
}

func (a *activity) seen(att workloadidentity.Attestation, now time.Time) {
	if a == nil || att.PodUID == "" {
		return
	}
	a.mu.Lock()
	a.pods[att.PodUID] = activityEntry{namespace: att.Namespace, owner: att.OwnerUID, lastSeen: now}
	a.mu.Unlock()
}

// forget drops a Pod that left the cache: its controller no longer runs it.
func (a *activity) forget(podUID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	delete(a.pods, podUID)
	a.mu.Unlock()
}

// ActivityReport is the admin listener's one response.
type ActivityReport struct {
	// ReplicaStarted is when this replica began recording. A Pod absent from
	// Pods has not used this replica since then.
	ReplicaStarted time.Time     `json:"replicaStarted"`
	Pods           []PodActivity `json:"pods"`
}

// PodActivity is one agent Pod's last use of this replica.
type PodActivity struct {
	Namespace string    `json:"namespace"`
	PodUID    string    `json:"podUID"`
	OwnerUID  string    `json:"ownerUID"`
	LastSeen  time.Time `json:"lastSeen"`
}

func (a *activity) report() ActivityReport {
	a.mu.Lock()
	out := ActivityReport{ReplicaStarted: a.started.UTC(), Pods: make([]PodActivity, 0, len(a.pods))}
	for uid, e := range a.pods {
		out.Pods = append(out.Pods, PodActivity{Namespace: e.namespace, PodUID: uid, OwnerUID: e.owner, LastSeen: e.lastSeen.UTC()})
	}
	a.mu.Unlock()
	sort.Slice(out.Pods, func(i, j int) bool { return out.Pods[i].PodUID < out.Pods[j].PodUID })
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
		_ = json.NewEncoder(w).Encode(a.report())
	})
}

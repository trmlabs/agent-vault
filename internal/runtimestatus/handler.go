// Package runtimestatus defines a read-only cleanup observation, broker-wide or
// for one requested agent.
// Server exposure is opt-in and requires a dedicated live workload authorizer
// and a consistent broker/cleanup snapshot. No default observer is installed.
package runtimestatus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Observation contains no credential, lease, binding or session identifiers.
// Actor and workload identifiers key Attributed; the handler serializes them
// only to a caller whose authorization grants the agent list. Consistent must
// be false if admission changed during the snapshot. Healthy includes current
// cleanup ownership and provider authorization, not just a running listener.
// Zero counts do not prove database-side absence.
type Observation struct {
	Initialized       bool
	Healthy           bool
	Consistent        bool
	ActiveConnections int
	UnfinishedCleanup int
	UnknownCleanup    int
	// Attributed partitions the totals by the actor and runtime instance that
	// caused them. An entry with an empty WorkloadID counts against every
	// instance of its actor. Unattributed holds connections not yet
	// authenticated and cleanup records with no actor (written before
	// attribution existed); they count against every actor.
	Attributed   map[Attribution]Counts
	Unattributed Counts
}

// Attribution names who caused a connection or cleanup record. ActorID is
// never empty in Observation.Attributed.
type Attribution struct{ ActorID, WorkloadID string }

// Counts is one attribution's share of an Observation.
type Counts struct {
	ActiveConnections int
	UnfinishedCleanup int
	UnknownCleanup    int
}

func (c Counts) add(other Counts) Counts {
	return Counts{c.ActiveConnections + other.ActiveConnections, c.UnfinishedCleanup + other.UnfinishedCleanup, c.UnknownCleanup + other.UnknownCleanup}
}

// ForActor returns the counts that gate admission for one actor: its own
// across every instance, plus every unattributed connection and record, so
// unknown ownership fails closed.
func (o Observation) ForActor(actorID string) Counts {
	total := o.Unattributed
	for owner, c := range o.Attributed {
		if owner.ActorID == actorID {
			total = total.add(c)
		}
	}
	return total
}

// partitioned reports whether the attributed counts sum exactly to the totals,
// so a per-agent answer cannot omit anything the totals include.
func (o Observation) partitioned() bool {
	sum := o.Unattributed
	for owner, c := range o.Attributed {
		if owner.ActorID == "" || !c.valid() {
			return false
		}
		sum = sum.add(c)
	}
	return o.Unattributed.valid() && sum == Counts{o.ActiveConnections, o.UnfinishedCleanup, o.UnknownCleanup}
}

func (c Counts) valid() bool {
	return c.ActiveConnections >= 0 && c.UnfinishedCleanup >= 0 && c.UnknownCleanup >= 0 && c.UnknownCleanup <= c.UnfinishedCleanup
}

func (c Counts) status() string {
	switch {
	case c.UnknownCleanup != 0:
		return "unknown"
	case c.ActiveConnections == 0 && c.UnfinishedCleanup == 0:
		return "ready"
	default:
		return "pending"
	}
}

type Snapshot func(context.Context) (Observation, error)

// Access is what a verified observer proof may read beyond the totals.
type Access struct {
	// ListAgents permits the agents=all view, which names every actor and
	// runtime instance with outstanding work. Grant it only to the admission
	// controller that created those agents.
	ListAgents bool
}

// Authorize must verify a dedicated observer's current workload proof and live
// Pod against operator-owned policy, and return that binding's access. It must
// not use owner tokens or give the observer a proxy grant. The HTTP handler
// supplies no fallback authentication.
type Authorize func(context.Context, string) (Access, error)

// Grants reports whether every configured proxy workload binding still holds
// its vault grant. It returns no identifiers, only the aggregate answer.
type Grants func(context.Context) (bool, error)

type response struct {
	SchemaVersion     int    `json:"schemaVersion"`
	Status            string `json:"status"`
	ActiveConnections int    `json:"activeConnections"`
	UnfinishedCleanup int    `json:"unfinishedCleanup"`
	UnknownCleanup    int    `json:"unknownCleanup"`
	ObservedAt        string `json:"observedAt"`
	// ProxyGrants is "authorized", "missing" or "unknown" when a Grants check
	// is configured, so a caller can refuse to admit a workload the broker
	// would deny. Omitted otherwise.
	ProxyGrants string `json:"proxyGrants,omitempty"`
	// Agent answers for the actor named by the agent query parameter. Omitted
	// without one, so existing responses are unchanged.
	Agent *agentResponse `json:"agent,omitempty"`
	// agentList fields appear only for agents=all, and only when the snapshot
	// partitions exactly; their absence means the list is unknown.
	*agentList
}

type agentResponse struct {
	Status            string `json:"status"`
	ActiveConnections int    `json:"activeConnections"`
	UnfinishedCleanup int    `json:"unfinishedCleanup"`
	UnknownCleanup    int    `json:"unknownCleanup"`
}

// agentList reports unattributed work once instead of folding it into each
// entry. The caller must treat any unattributed count as blocking every agent,
// and an entry with an empty workloadUID as blocking every instance of its agent.
type agentList struct {
	Agents                     []agentEntry `json:"agents"`
	UnattributedConnections    int          `json:"unattributedConnections"`
	UnattributedCleanup        int          `json:"unattributedCleanup"`
	UnattributedUnknownCleanup int          `json:"unattributedUnknownCleanup"`
}

type agentEntry struct {
	AgentID           string `json:"agentID"`
	WorkloadUID       string `json:"workloadUID"`
	ActiveConnections int    `json:"activeConnections"`
	UnfinishedCleanup int    `json:"unfinishedCleanup"`
	UnknownCleanup    int    `json:"unknownCleanup"`
}

func newAgentList(o Observation) *agentList {
	list := &agentList{Agents: make([]agentEntry, 0, len(o.Attributed)), UnattributedConnections: o.Unattributed.ActiveConnections,
		UnattributedCleanup: o.Unattributed.UnfinishedCleanup, UnattributedUnknownCleanup: o.Unattributed.UnknownCleanup}
	for owner, c := range o.Attributed {
		if c == (Counts{}) {
			continue
		}
		list.Agents = append(list.Agents, agentEntry{AgentID: owner.ActorID, WorkloadUID: owner.WorkloadID,
			ActiveConnections: c.ActiveConnections, UnfinishedCleanup: c.UnfinishedCleanup, UnknownCleanup: c.UnknownCleanup})
	}
	sort.Slice(list.Agents, func(i, j int) bool {
		a, b := list.Agents[i], list.Agents[j]
		return a.AgentID < b.AgentID || a.AgentID == b.AgentID && a.WorkloadUID < b.WorkloadUID
	})
	return list
}

const maxAgentIDLength = 128

type query struct {
	agentID string // one agent's view
	list    bool   // agents=all
}

// parseQuery accepts no query, exactly one well-formed agent parameter, or
// agents=all. The two views are mutually exclusive.
func parseQuery(raw string) (query, bool) {
	if raw == "" {
		return query{}, true
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != 1 {
		return query{}, false
	}
	if all := values["agents"]; len(all) == 1 && all[0] == "all" {
		return query{list: true}, true
	}
	if len(values["agent"]) != 1 {
		return query{}, false
	}
	id := values["agent"][0]
	if id == "" || len(id) > maxAgentIDLength {
		return query{}, false
	}
	for _, r := range id {
		if !agentIDRune(r) {
			return query{}, false
		}
	}
	return query{agentID: id}, true
}

// New returns an isolated handler, not a server route. Callers must first stop
// old admission, then obtain this observation over verified transport from the
// expected dedicated broker. A ready response is reconciliation state only;
// independent database evidence remains necessary for acceptance.
func New(authorize Authorize, snapshot Snapshot, grants ...Grants) (http.Handler, error) {
	if len(grants) > 1 || (len(grants) == 1 && grants[0] == nil) {
		return nil, errors.New("at most one grants check")
	}
	if authorize == nil || snapshot == nil {
		return nil, errors.New("observer authorization and snapshot required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/runtime/cleanup-status" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		q, ok := parseQuery(r.URL.RawQuery)
		if !ok || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		proof := strings.TrimPrefix(headers[0], "Bearer ")
		if proof == "" || len(proof) > 32768 || strings.ContainsAny(proof, " \t\r\n,") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		access, err := authorize(ctx, proof)
		if err != nil || ctx.Err() != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if q.list && !access.ListAgents {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		observation, err := snapshot(ctx)
		result := response{SchemaVersion: 1, Status: "unknown", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		code := http.StatusServiceUnavailable
		if q.agentID != "" {
			result.Agent = &agentResponse{Status: "unknown"}
		}
		totals := Counts{observation.ActiveConnections, observation.UnfinishedCleanup, observation.UnknownCleanup}
		if err == nil && ctx.Err() == nil && observation.Initialized && observation.Healthy && observation.Consistent && totals.valid() {
			result.ActiveConnections = totals.ActiveConnections
			result.UnfinishedCleanup = totals.UnfinishedCleanup
			result.UnknownCleanup = totals.UnknownCleanup
			result.Status = totals.status()
			if result.Status != "unknown" {
				code = http.StatusOK
			}
			if q.list {
				// The list keeps the broker-wide status code. A snapshot whose
				// partition disagrees with its totals cannot be listed.
				if observation.partitioned() {
					result.agentList = newAgentList(observation)
				} else {
					result.Status, code = "unknown", http.StatusServiceUnavailable
				}
			}
			if q.agentID != "" {
				// With an agent, the status code answers for that agent alone.
				// A snapshot whose partition disagrees with its totals cannot.
				code = http.StatusServiceUnavailable
				if observation.partitioned() {
					counts := observation.ForActor(q.agentID)
					result.Agent = &agentResponse{Status: counts.status(), ActiveConnections: counts.ActiveConnections, UnfinishedCleanup: counts.UnfinishedCleanup, UnknownCleanup: counts.UnknownCleanup}
					if result.Agent.Status != "unknown" {
						code = http.StatusOK
					}
				}
			}
		}
		if len(grants) == 1 {
			result.ProxyGrants = "unknown"
			if authorized, err := grants[0](ctx); err == nil && ctx.Err() == nil {
				result.ProxyGrants = "missing"
				if authorized {
					result.ProxyGrants = "authorized"
				}
			}
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(result)
	}), nil
}

// agentIDRune allows agent UUIDs and the "pool:<name>" owner of a pooled credential.
func agentIDRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':'
}

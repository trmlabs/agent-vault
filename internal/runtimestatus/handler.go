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
	"strings"
	"time"
)

// Observation contains no credential, lease, binding or session identifiers.
// Actor identifiers key Actors only so the handler can answer for one requested
// actor; they are never serialized. Consistent must be false if admission
// changed during the snapshot. Healthy includes current cleanup ownership and
// provider authorization, not just a running listener. Zero counts do not
// prove database-side absence.
type Observation struct {
	Initialized       bool
	Healthy           bool
	Consistent        bool
	ActiveConnections int
	UnfinishedCleanup int
	UnknownCleanup    int
	// Actors partitions the totals by the actor that caused them. Unattributed
	// holds connections not yet authenticated and cleanup records with no actor
	// (written before attribution existed); they count against every actor.
	Actors       map[string]Counts
	Unattributed Counts
}

// Counts is one actor's share of an Observation.
type Counts struct {
	ActiveConnections int
	UnfinishedCleanup int
	UnknownCleanup    int
}

// ForActor returns the counts that gate admission for one actor: its own plus
// every unattributed connection and record, so unknown ownership fails closed.
func (o Observation) ForActor(actorID string) Counts {
	own := o.Actors[actorID]
	return Counts{
		ActiveConnections: own.ActiveConnections + o.Unattributed.ActiveConnections,
		UnfinishedCleanup: own.UnfinishedCleanup + o.Unattributed.UnfinishedCleanup,
		UnknownCleanup:    own.UnknownCleanup + o.Unattributed.UnknownCleanup,
	}
}

// partitioned reports whether the per-actor counts sum exactly to the totals,
// so a requested actor's answer cannot omit anything the totals include.
func (o Observation) partitioned() bool {
	sum := o.Unattributed
	for _, c := range o.Actors {
		if !c.valid() {
			return false
		}
		sum.ActiveConnections += c.ActiveConnections
		sum.UnfinishedCleanup += c.UnfinishedCleanup
		sum.UnknownCleanup += c.UnknownCleanup
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

// Authorize must verify a dedicated observer's current workload proof and live
// Pod against operator-owned policy. It must not use owner tokens or give the
// observer a proxy grant. The HTTP handler supplies no fallback authentication.
type Authorize func(context.Context, string) error

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
}

type agentResponse struct {
	Status            string `json:"status"`
	ActiveConnections int    `json:"activeConnections"`
	UnfinishedCleanup int    `json:"unfinishedCleanup"`
	UnknownCleanup    int    `json:"unknownCleanup"`
}

const maxAgentIDLength = 128

// agentQuery accepts no query, or exactly one well-formed agent parameter.
func agentQuery(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != 1 || len(values["agent"]) != 1 {
		return "", false
	}
	id := values["agent"][0]
	if id == "" || len(id) > maxAgentIDLength {
		return "", false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", false
		}
	}
	return id, true
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
		agentID, ok := agentQuery(r.URL.RawQuery)
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
		if authorize(ctx, proof) != nil || ctx.Err() != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		observation, err := snapshot(ctx)
		result := response{SchemaVersion: 1, Status: "unknown", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		code := http.StatusServiceUnavailable
		if agentID != "" {
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
			if agentID != "" {
				// With an agent, the status code answers for that agent alone.
				// A snapshot whose partition disagrees with its totals cannot.
				code = http.StatusServiceUnavailable
				if observation.partitioned() {
					counts := observation.ForActor(agentID)
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

// Package runtimestatus defines a read-only, broker-wide cleanup observation.
// Server exposure is opt-in and requires a dedicated live workload authorizer
// and a consistent broker/cleanup snapshot. No default observer is installed.
package runtimestatus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Observation contains no credential, lease, actor, binding or session identifiers.
// Consistent must be false if admission changed during the snapshot. Healthy
// includes current cleanup ownership and provider authorization, not just a
// running listener. Zero counts do not prove database-side absence.
type Observation struct {
	Initialized       bool
	Healthy           bool
	Consistent        bool
	ActiveConnections int
	UnfinishedCleanup int
	UnknownCleanup    int
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
		if r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
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
		if err == nil && ctx.Err() == nil && observation.Initialized && observation.Healthy && observation.Consistent && observation.ActiveConnections >= 0 && observation.UnfinishedCleanup >= 0 && observation.UnknownCleanup >= 0 && observation.UnknownCleanup <= observation.UnfinishedCleanup {
			result.ActiveConnections = observation.ActiveConnections
			result.UnfinishedCleanup = observation.UnfinishedCleanup
			result.UnknownCleanup = observation.UnknownCleanup
			if result.UnknownCleanup == 0 {
				code = http.StatusOK
				result.Status = "pending"
				if result.ActiveConnections == 0 && result.UnfinishedCleanup == 0 {
					result.Status = "ready"
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

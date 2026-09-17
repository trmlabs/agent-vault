package requestlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/store"
)

// Attempt contains only approved identifiers. Callers must source actor, vault,
// service, mapping and destination from verified identity and configuration,
// never from request headers, URLs, bodies, or workload tokens.
// A request path is deliberately absent: even a path can contain a credential.
type Attempt struct {
	VaultID     string
	ActorType   string
	ActorID     string
	WorkloadID  string // verified runtime instance identifier, optional
	Destination string // configured host, optionally with port; never a URL
	Service     string
	MappingIDs  []string
	Method      string
	Decision    string // allow or deny
}

// Outcome contains only a fixed result and HTTP status, never upstream error text.
type Outcome struct {
	Result string // completed, denied, or upstream_error
	Status int
}

// Durable acknowledges storage before the caller opens an outbound connection.
// Finish failure cannot undo a destination action. The attempt remains unknown;
// callers must never replay an outbound request to repair an audit record.
type Durable interface {
	Begin(context.Context, Attempt) (string, error)
	Finish(context.Context, string, Outcome) error
}

type auditStore interface {
	InsertProxyAudit(context.Context, store.ProxyAudit) error
	CompleteProxyAudit(context.Context, string, string, int) error
}

type durableSink struct{ store auditStore }

// NewDurable uses the application's persistent SQL store rather than the lossy
// request-log batch queue. Unsupported stores fail closed at Begin.
func NewDurable(s any) Durable {
	a, _ := s.(auditStore)
	return &durableSink{store: a}
}

var ErrAuditUnavailable = errors.New("durable request audit unavailable")
var ErrInvalidAudit = errors.New("invalid request audit metadata")

func (s *durableSink) Begin(ctx context.Context, a Attempt) (string, error) {
	if !validAttempt(a) {
		return "", ErrInvalidAudit
	}
	if s.store == nil {
		return "", ErrAuditUnavailable
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrAuditUnavailable
	}
	id := hex.EncodeToString(b[:])
	row := store.ProxyAudit{RequestID: id, VaultID: a.VaultID, ActorType: a.ActorType, ActorID: a.ActorID, WorkloadID: a.WorkloadID, Destination: a.Destination, Service: a.Service, MappingIDs: append([]string(nil), a.MappingIDs...), Method: a.Method, Decision: a.Decision}
	if err := s.store.InsertProxyAudit(ctx, row); err != nil {
		return "", ErrAuditUnavailable
	}
	return id, nil
}

func (s *durableSink) Finish(ctx context.Context, id string, o Outcome) error {
	if !identifier(id, false) || (o.Result != "completed" && o.Result != "denied" && o.Result != "upstream_error") || o.Status < 100 || o.Status > 599 {
		return ErrInvalidAudit
	}
	if s.store == nil {
		return ErrAuditUnavailable
	}
	if err := s.store.CompleteProxyAudit(ctx, id, o.Result, o.Status); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func validAttempt(a Attempt) bool {
	if a.Decision != "allow" && a.Decision != "deny" {
		return false
	}
	if a.ActorType != "agent" && a.ActorType != "user" && a.ActorType != "workload" && a.ActorType != "unknown" {
		return false
	}
	// Empty metadata is useful for denials before authentication or service match.
	optional := a.Decision == "deny"
	if !identifier(a.WorkloadID, true) {
		return false
	}
	if !identifier(a.VaultID, optional) || !identifier(a.ActorID, optional) || !identifier(a.Service, optional) {
		return false
	}
	if a.Destination != "" || !optional {
		if !validDestination(a.Destination) {
			return false
		}
	}
	switch a.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	case "UNKNOWN":
		if !optional {
			return false
		}
	default:
		return false
	}
	if len(a.MappingIDs) > 128 {
		return false
	}
	for _, id := range a.MappingIDs {
		if !identifier(id, false) {
			return false
		}
	}
	return true
}

func identifier(s string, optional bool) bool {
	if s == "" {
		return optional
	}
	if len(s) > 256 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("_-.:@/", c) {
			return false
		}
	}
	return true
}

func validDestination(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "/@?#%\\ \t\n\r") {
		return false
	}
	host := s
	if strings.Contains(s, ":") {
		if net.ParseIP(s) != nil {
			return true
		}
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		host = h
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

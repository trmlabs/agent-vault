// Package actionref provides a local acceptance reference for fixed read actions.
// It is not wired into the server. Deployment must supply a trusted identity
// verifier, an authoritative policy store, and an isolated credential proxy.
package actionref

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Identity struct {
	Actor, Run string
	Expires    time.Time
}

// Verify and Allow must respect context cancellation and read current authority.
type Config struct {
	Verify                           func(context.Context, string) (Identity, error)
	Allow                            func(context.Context, Identity) (bool, error)
	Client                           *http.Client
	Upstream                         string
	Fields                           []string
	Poll, LookupTimeout, MaxDuration time.Duration
}

var errDenied = errors.New("access withdrawn")

// New serves only POST /actions/read with an empty body and no query string.
// Upstream routing and output fields are configured by trusted code.
func New(c Config) (http.Handler, error) {
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || c.Verify == nil || c.Allow == nil || c.Client == nil || len(c.Fields) == 0 {
		return nil, errors.New("invalid action reference configuration")
	}
	if c.Poll <= 0 {
		c.Poll = 5 * time.Second
	}
	if c.LookupTimeout <= 0 {
		c.LookupTimeout = 2 * time.Second
	}
	if c.MaxDuration <= 0 {
		c.MaxDuration = 60 * time.Second
	}
	client := *c.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fields := append([]string(nil), c.Fields...)
	busy := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func(status int, message string) { http.Error(w, message, status) }
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost || r.URL.Path != "/actions/read" || r.URL.RawQuery != "" {
			deny(http.StatusBadRequest, "unsupported action")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			deny(http.StatusBadRequest, "parameters not allowed")
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || token == r.Header.Get("Authorization") {
			deny(http.StatusUnauthorized, "identity required")
			return
		}
		lookup, stop := context.WithTimeout(r.Context(), c.LookupTimeout)
		id, err := c.Verify(lookup, token)
		lookupErr := lookup.Err()
		stop()
		if err != nil || lookupErr != nil || id.Actor == "" || id.Run == "" || !time.Now().Before(id.Expires) {
			deny(http.StatusUnauthorized, "invalid identity")
			return
		}
		allowed := func(ctx context.Context) bool {
			ctx, cancel := context.WithTimeout(ctx, c.LookupTimeout)
			defer cancel()
			current, err := c.Verify(ctx, token)
			if err != nil || current.Actor != id.Actor || current.Run != id.Run || !time.Now().Before(current.Expires) {
				return false
			}
			ok, err := c.Allow(ctx, id)
			return err == nil && ctx.Err() == nil && ok
		}
		if !allowed(r.Context()) {
			deny(http.StatusForbidden, "action denied")
			return
		}
		select {
		case busy <- struct{}{}:
			defer func() { <-busy }()
		default:
			deny(http.StatusTooManyRequests, "action busy")
			return
		}
		deadline := time.Now().Add(c.MaxDuration)
		if id.Expires.Before(deadline) {
			deadline = id.Expires
		}
		bounded, cancelDeadline := context.WithDeadline(r.Context(), deadline)
		defer cancelDeadline()
		ctx, cancel := context.WithCancelCause(bounded)
		defer cancel(nil)
		finished := make(chan struct{})
		defer func() { cancel(nil); <-finished }()
		go func() {
			defer close(finished)
			ticker := time.NewTicker(c.Poll)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if !allowed(ctx) {
						cancel(errDenied)
						return
					}
				}
			}
		}()
		fail := func() {
			switch {
			case errors.Is(context.Cause(ctx), errDenied):
				deny(http.StatusForbidden, "action denied")
			case errors.Is(context.Cause(ctx), context.DeadlineExceeded):
				deny(http.StatusGatewayTimeout, "action expired")
			default:
				deny(http.StatusBadGateway, "upstream failed")
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Upstream, nil)
		if err != nil {
			fail()
			return
		}
		response, err := client.Do(request)
		if err != nil {
			fail()
			return
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			fail()
			return
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(payload) > 65536 {
			fail()
			return
		}
		var data map[string]json.RawMessage
		if json.Unmarshal(payload, &data) != nil {
			fail()
			return
		}
		out := map[string]json.RawMessage{}
		for _, key := range fields {
			if value, ok := data[key]; ok {
				out[key] = value
			}
		}
		if ctx.Err() != nil {
			fail()
			return
		}
		if !allowed(ctx) {
			deny(http.StatusForbidden, "action denied")
			return
		}
		if ctx.Err() != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}), nil
}

package actionref

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActionRestrictions(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("caller identity forwarded upstream")
		}
		_, _ = io.WriteString(w, `{"result":"approved","secret":"canary"}`)
	}))
	defer upstream.Close()
	var policy atomic.Int32
	h, err := New(Config{Client: upstream.Client(), Upstream: upstream.URL, Fields: []string{"result"},
		Verify: func(_ context.Context, token string) (Identity, error) {
			if token == "bad" {
				return Identity{}, errors.New("invalid")
			}
			expires := time.Now().Add(time.Minute)
			if token == "expired" {
				expires = time.Now().Add(-time.Minute)
			}
			return Identity{Actor: "actor", Run: "run", Expires: expires}, nil
		},
		Allow: func(context.Context, Identity) (bool, error) {
			if policy.Load() == 2 {
				return false, errors.New("unavailable")
			}
			return policy.Load() == 0, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	run := func(path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := run("/actions/read", "valid", ""); w.Code != 200 || w.Body.String() != "{\"result\":\"approved\"}\n" || calls.Load() != 1 {
		t.Fatalf("positive control: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name, path, token, body string
		policy                  int32
		status                  int
	}{
		{"identity", "/actions/read", "bad", "", 0, 401},
		{"expiry", "/actions/read", "expired", "", 0, 401},
		{"operation", "/actions/other", "valid", "", 0, 400},
		{"destination", "/actions/read?url=http://elsewhere", "valid", "", 0, 400},
		{"parameters", "/actions/read", "valid", "{}", 0, 400},
		{"permission", "/actions/read", "valid", "", 1, 403},
		{"policy-outage", "/actions/read", "valid", "", 2, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy.Store(tc.policy)
			w := run(tc.path, tc.token, tc.body)
			if w.Code != tc.status || calls.Load() != 1 {
				t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
			}
		})
	}
}

func TestUpstreamRestrictions(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer target.Close()
	for _, mode := range []string{"redirect", "oversize", "malformed", "failure"} {
		t.Run(mode, func(t *testing.T) {
			u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("x", 65537))
				case "malformed":
					_, _ = io.WriteString(w, "not json")
				case "failure":
					http.Error(w, "secret-canary", 500)
				}
			}))
			defer u.Close()
			h, err := New(Config{Client: u.Client(), Upstream: u.URL, Fields: []string{"result"}, Verify: func(context.Context, string) (Identity, error) {
				return Identity{"actor", "run", time.Now().Add(time.Minute)}, nil
			}, Allow: func(context.Context, Identity) (bool, error) { return true, nil }})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/actions/read", nil)
			r.Header.Set("Authorization", "Bearer fixture")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 502 || w.Body.String() != "upstream failed\n" || followed.Load() != 0 {
				t.Fatalf("unsafe upstream response: %d", w.Code)
			}
		})
	}
}

func TestLookupDeadline(t *testing.T) {
	for _, stage := range []string{"identity", "policy"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer upstream.Close()
			h, err := New(Config{
				Client: upstream.Client(), Upstream: upstream.URL, Fields: []string{"result"}, LookupTimeout: 20 * time.Millisecond,
				Verify: func(ctx context.Context, token string) (Identity, error) {
					if stage == "identity" {
						<-ctx.Done()
					}
					return Identity{"actor", "run", time.Now().Add(time.Minute)}, nil
				},
				Allow: func(ctx context.Context, id Identity) (bool, error) { <-ctx.Done(); return true, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/actions/read", nil)
			r.Header.Set("Authorization", "Bearer fixture")
			w := httptest.NewRecorder()
			start := time.Now()
			h.ServeHTTP(w, r)
			want := 403
			if stage == "identity" {
				want = 401
			}
			if w.Code != want || calls.Load() != 0 || time.Since(start) > time.Second {
				t.Fatalf("lookup timeout did not fail closed: status=%d calls=%d", w.Code, calls.Load())
			}
		})
	}
}

package httpcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// GCPToken is a minted Google access token. It prints as its expiry only.
type GCPToken struct {
	value   string
	life    time.Duration
	Expires time.Time
}

func (t GCPToken) Value() string { return t.value }
func (t GCPToken) String() string {
	return "gcp-token(expires " + t.Expires.UTC().Format(time.RFC3339) + ")"
}
func (t GCPToken) GoString() string           { return t.String() }
func (t GCPToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.String())) }

// GCPTokens mints per-entry Google tokens from the broker's own identity and
// caches each until a quarter of its use remains.
type GCPTokens struct {
	// Root is the broker's own identity (Workload Identity on GKE).
	Root oauth2.TokenSource
	// Client reaches STS and IAM Credentials; it must dial only Google.
	Client *http.Client
	// STSURL and IAMCredentialsURL default to Google's endpoints.
	STSURL, IAMCredentialsURL string
	Now                       func() time.Time

	mu     sync.Mutex
	cache  map[string]GCPToken
	flight map[string]*sync.Mutex
}

var ErrGCPToken = errors.New("google token unavailable")

func (g *GCPTokens) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *GCPTokens) fresh(t GCPToken) bool {
	left := t.Expires.Sub(g.now())
	return left > time.Minute && left > t.life/4
}

func gcpCacheKey(e *Entry) string {
	b := e.GCP
	return strings.Join([]string{e.Name, b.Bucket, b.Prefix, b.Role, b.ServiceAccount, strings.Join(b.Scopes, " ")}, "\x00")
}

// Token returns the current token for a gcp entry. Concurrent misses for one
// entry share a single mint.
func (g *GCPTokens) Token(ctx context.Context, e *Entry) (GCPToken, error) {
	if e == nil || e.GCP == nil || g.Root == nil || g.Client == nil {
		return GCPToken{}, ErrGCPToken
	}
	key := gcpCacheKey(e)
	g.mu.Lock()
	if g.cache == nil {
		g.cache, g.flight = map[string]GCPToken{}, map[string]*sync.Mutex{}
	}
	if t, ok := g.cache[key]; ok && g.fresh(t) {
		g.mu.Unlock()
		return t, nil
	}
	flight := g.flight[key]
	if flight == nil {
		flight = &sync.Mutex{}
		g.flight[key] = flight
	}
	g.mu.Unlock()
	flight.Lock()
	defer flight.Unlock()
	g.mu.Lock()
	if t, ok := g.cache[key]; ok && g.fresh(t) {
		g.mu.Unlock()
		return t, nil
	}
	g.mu.Unlock()
	root, err := g.Root.Token()
	if err != nil || root.AccessToken == "" {
		return GCPToken{}, ErrGCPToken
	}
	var t GCPToken
	if e.GCP.Bucket != "" {
		t, err = g.downscope(ctx, e.GCP, root)
	} else {
		t, err = g.impersonate(ctx, e.GCP, root)
	}
	if err != nil {
		return GCPToken{}, ErrGCPToken
	}
	g.mu.Lock()
	g.cache[key] = t
	g.mu.Unlock()
	return t, nil
}

// Invalidate drops an entry's token after Google refused it.
func (g *GCPTokens) Invalidate(e *Entry) {
	g.mu.Lock()
	delete(g.cache, gcpCacheKey(e))
	g.mu.Unlock()
}

// AccessBoundary is the Credential Access Boundary for a downscoped entry:
// one bucket, objects under one prefix (and listings of that prefix), one
// object role. Bucket and prefix are validated to characters that cannot
// break out of the CEL string literals.
func AccessBoundary(b *GCPBinding) map[string]any {
	bucket := "projects/_/buckets/" + b.Bucket
	return map[string]any{"accessBoundary": map[string]any{"accessBoundaryRules": []any{map[string]any{
		"availableResource":    "//storage.googleapis.com/" + bucket,
		"availablePermissions": []string{"inRole:" + b.Role},
		"availabilityCondition": map[string]string{
			"title": "gatehouse-entry-prefix",
			"expression": "resource.name.startsWith('" + bucket + "/objects/" + b.Prefix + "') || " +
				"api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('" + b.Prefix + "')",
		},
	}}}}
}

func (g *GCPTokens) downscope(ctx context.Context, b *GCPBinding, root *oauth2.Token) (GCPToken, error) {
	options, _ := json.Marshal(AccessBoundary(b))
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {root.AccessToken},
		"options":              {string(options)},
	}
	endpoint := g.STSURL
	if endpoint == "" {
		endpoint = "https://sts.googleapis.com/v1/token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return GCPToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := g.call(req, &out); err != nil || out.AccessToken == "" {
		return GCPToken{}, ErrGCPToken
	}
	// A downscoped token lives no longer than the token it came from.
	expires := root.Expiry
	if out.ExpiresIn > 0 {
		if e := g.now().Add(time.Duration(out.ExpiresIn) * time.Second); expires.IsZero() || e.Before(expires) {
			expires = e
		}
	}
	return g.bounded(out.AccessToken, expires, b.LifetimeSeconds)
}

func (g *GCPTokens) impersonate(ctx context.Context, b *GCPBinding, root *oauth2.Token) (GCPToken, error) {
	body, _ := json.Marshal(map[string]any{"scope": b.Scopes, "lifetime": strconv.Itoa(b.LifetimeSeconds) + "s"})
	endpoint := g.IAMCredentialsURL
	if endpoint == "" {
		endpoint = "https://iamcredentials.googleapis.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/projects/-/serviceAccounts/"+url.PathEscape(b.ServiceAccount)+":generateAccessToken", bytes.NewReader(body))
	if err != nil {
		return GCPToken{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+root.AccessToken)
	var out struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if err := g.call(req, &out); err != nil || out.AccessToken == "" || out.ExpireTime.IsZero() {
		return GCPToken{}, ErrGCPToken
	}
	return g.bounded(out.AccessToken, out.ExpireTime, b.LifetimeSeconds)
}

// bounded uses a token for at most the entry's lifetime, and never past its
// own expiry.
func (g *GCPTokens) bounded(value string, expires time.Time, lifetimeSeconds int) (GCPToken, error) {
	now := g.now()
	limit := now.Add(time.Duration(lifetimeSeconds) * time.Second)
	if expires.IsZero() || limit.Before(expires) {
		expires = limit
	}
	if expires.Sub(now) < 2*time.Minute {
		return GCPToken{}, ErrGCPToken
	}
	return GCPToken{value: value, life: expires.Sub(now), Expires: expires}, nil
}

func (g *GCPTokens) call(req *http.Request, out any) error {
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		// Google's error text is not passed on: it can name the principal.
		return fmt.Errorf("google token endpoint answered %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

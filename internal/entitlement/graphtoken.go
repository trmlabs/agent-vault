package entitlement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// GraphEndpoint is Microsoft Graph's v1.0 API.
const GraphEndpoint = "https://graph.microsoft.com/v1.0"

// EntraLogin is the Microsoft identity platform host. It is fixed, not
// configurable: the assertion it receives is the broker's own identity.
const EntraLogin = "https://login.microsoftonline.com"

// FederatedToken gets a Microsoft Graph application token with workload
// identity federation: the broker's projected Kubernetes service-account token
// (audience api://AzureADTokenExchange) is the client assertion, so the Entra
// app holds no secret. The file is read on every exchange because the kubelet
// rotates it. Neither the assertion nor the token is ever logged or returned
// in an error.
type FederatedToken struct {
	TenantID      string
	ClientID      string
	AssertionFile string
	Client        *http.Client
	// Login overrides EntraLogin in tests only.
	Login string
	// Now overrides time.Now in tests only.
	Now func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenRefreshMargin renews a token this long before Entra says it expires,
// so a lookup never carries one that lapses in flight.
const tokenRefreshMargin = 5 * time.Minute

// maxAssertionBytes bounds the file read; a projected token is a few KB.
const maxAssertionBytes = 64 << 10

// Token returns a cached Graph token, exchanging the assertion when none is
// cached or the cached one is within the refresh margin of expiry.
func (f *FederatedToken) Token(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if f.token != "" && now.Add(tokenRefreshMargin).Before(f.expires) {
		return f.token, nil
	}
	token, lifetime, err := f.exchange(ctx)
	if err != nil {
		f.token, f.expires = "", time.Time{}
		return "", err
	}
	f.token, f.expires = token, now.Add(lifetime)
	return token, nil
}

func (f *FederatedToken) exchange(ctx context.Context) (string, time.Duration, error) {
	assertion, err := readAssertion(f.AssertionFile)
	if err != nil {
		return "", 0, err
	}
	login := f.Login
	if login == "" {
		login = EntraLogin
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {f.ClientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	endpoint := login + "/" + url.PathEscape(f.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", 0, errors.New("directory token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, errors.New("directory token exchange unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, errors.New("directory token exchange unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		// Entra's error code (for example AADSTS70021, no matching federated
		// credential) names the cause without echoing the assertion.
		var e struct {
			Error string `json:"error"`
			Codes []int  `json:"error_codes"`
		}
		_ = json.Unmarshal(data, &e)
		return "", 0, fmt.Errorf("directory token exchange returned %d %s %v", resp.StatusCode, e.Error, e.Codes)
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" || !strings.EqualFold(out.TokenType, "Bearer") {
		return "", 0, errors.New("directory token exchange returned no bearer token")
	}
	seconds, err := expiresIn(out.ExpiresIn)
	if err != nil {
		return "", 0, err
	}
	return out.AccessToken, time.Duration(seconds) * time.Second, nil
}

// expiresIn accepts Entra's expires_in as a number or a numeric string.
func expiresIn(raw json.RawMessage) (int64, error) {
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			return 0, errors.New("directory token has no lifetime")
		}
		if _, err := fmt.Sscan(s, &n); err != nil {
			return 0, errors.New("directory token has no lifetime")
		}
	}
	if n <= 0 {
		return 0, errors.New("directory token has no lifetime")
	}
	return n, nil
}

func readAssertion(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("workload identity token file unreadable")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAssertionBytes+1))
	if err != nil || len(data) > maxAssertionBytes {
		return "", errors.New("workload identity token file unreadable")
	}
	assertion := strings.TrimSpace(string(data))
	if assertion == "" {
		return "", errors.New("workload identity token file is empty")
	}
	return assertion, nil
}

func (f *FederatedToken) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

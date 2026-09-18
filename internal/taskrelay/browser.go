package taskrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BrowserOptions describes one controller-owned task, never agent input.
// Authorize must check the live pinned agent Pod UID and the actual socket peer.
// Audit must acknowledge local admission recording or return an error.
// The upstream browser broker remains the mandatory durable audit authority.
type BrowserOptions struct {
	Endpoint  string
	CA        []byte
	Task      string
	Deadline  time.Time
	Proof     func(context.Context) (string, error)
	Authorize func(context.Context, string) error
	Audit     func(context.Context, string, string) error
}

// BrowserRelay exposes only create/check/close for a single fixed browser task.
// Its broker handle and fresh workload proofs never enter agent responses.
type BrowserRelay struct {
	options   BrowserOptions
	client    *http.Client
	mu        sync.Mutex
	handle    string
	expiresAt int64
	closed    bool
	uncertain bool
}

var browserTaskName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var browserProof = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
var browserHandle = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var errBrowserUnavailable = errors.New("browser task unavailable")

func NewBrowserRelay(options BrowserOptions) (*BrowserRelay, error) {
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || !browserTaskName.MatchString(options.Task) || !options.Deadline.After(time.Now()) || options.Proof == nil || options.Authorize == nil || options.Audit == nil {
		return nil, errBrowserUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.CA) {
		return nil, errBrowserUnavailable
	}
	options.Endpoint = strings.TrimSuffix(options.Endpoint, "/")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, DisableCompression: true, Proxy: nil}
	return &BrowserRelay{options: options, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (b *BrowserRelay) allowed(ctx context.Context, peer string) error {
	if b.closed || !time.Now().Before(b.options.Deadline) {
		return errBrowserUnavailable
	}
	return b.options.Authorize(ctx, peer)
}

func browserError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"Browser task unavailable"}`)
}

func browserInput(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.IsAbs() || len(r.TransferEncoding) != 0 {
		return false
	}
	for name, values := range r.Header {
		switch strings.ToLower(name) {
		case "content-type", "accept", "accept-encoding", "user-agent", "content-length", "connection":
			if len(values) != 1 {
				return false
			}
		default:
			return false
		}
	}
	if r.Header.Get("Content-Type") != "application/json" {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 2049))
	if err != nil || len(data) > 2048 {
		return false
	}
	var value map[string]json.RawMessage
	return json.Unmarshal(data, &value) == nil && value != nil && len(value) == 0
}

// call sends only server-selected fields and reads only bounded JSON. No upstream
// headers or errors are copied into the agent response.
func (b *BrowserRelay) call(ctx context.Context, path string, input any, expectedStatus int, peer string) (map[string]json.RawMessage, error) {
	proof, err := b.options.Proof(ctx)
	if err != nil || len(proof) > 16377 || !browserProof.MatchString(proof) {
		return nil, errBrowserUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errBrowserUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.options.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, errBrowserUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+proof)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if peer != "" && b.allowed(ctx, peer) != nil {
		return nil, errBrowserUnavailable
	}
	response, err := b.client.Do(req)
	if err != nil {
		return nil, errBrowserUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != expectedStatus || mediaErr != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Location") != "" {
		return nil, errBrowserUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(data) > 2048 || bytes.Contains(data, []byte(proof)) {
		return nil, errBrowserUnavailable
	}
	// Reject duplicate fields, arrays, trailing JSON and unknown response shapes.
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errBrowserUnavailable
	}
	output := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || output[name] != nil {
			return nil, errBrowserUnavailable
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errBrowserUnavailable
		}
		output[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errBrowserUnavailable
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errBrowserUnavailable
	}
	return output, nil
}

// cleanup deliberately does not require an active pair: withdrawal must still
// attempt physical browser closure. Broker expiry remains the crash fallback.
func (b *BrowserRelay) cleanup(ctx context.Context) error {
	if b.handle == "" {
		return nil
	}
	result, err := b.call(ctx, "/v1/browser/close", map[string]string{"handle": b.handle}, http.StatusOK, "")
	var closed bool
	if err != nil || len(result) != 1 || json.Unmarshal(result["closed"], &closed) != nil || !closed {
		return errBrowserUnavailable
	}
	b.handle = ""
	b.expiresAt = 0
	return nil
}

func (b *BrowserRelay) refuseAndClose() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b.closed = true
	_ = b.cleanup(ctx)
}

func (b *BrowserRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := r.URL.Path
	if path != "/v1/browser/tasks" && path != "/v1/browser/check" && path != "/v1/browser/close" {
		browserError(w, http.StatusNotFound)
		return
	}
	if !browserInput(r) {
		browserError(w, http.StatusBadRequest)
		return
	}
	if !b.mu.TryLock() {
		browserError(w, http.StatusTooManyRequests)
		return
	}
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if b.allowed(ctx, r.RemoteAddr) != nil {
		// A wrong peer must not be able to terminate the legitimate task.
		// The controller independently closes the relay on actual pair loss.
		browserError(w, http.StatusForbidden)
		return
	}
	if b.uncertain {
		browserError(w, http.StatusConflict)
		return
	}
	if path == "/v1/browser/tasks" && b.handle != "" {
		browserError(w, http.StatusConflict)
		return
	}
	if path != "/v1/browser/tasks" && (b.handle == "" || b.expiresAt <= time.Now().UnixMilli()) {
		browserError(w, http.StatusConflict)
		return
	}
	if b.options.Audit(ctx, path, "attempt") != nil {
		browserError(w, http.StatusServiceUnavailable)
		return
	}
	if b.allowed(ctx, r.RemoteAddr) != nil {
		b.refuseAndClose()
		browserError(w, http.StatusForbidden)
		return
	}
	var payload any
	status := http.StatusOK
	var err error
	switch path {
	case "/v1/browser/tasks":
		var result map[string]json.RawMessage
		b.uncertain = true // A lost/malformed create response must never invite blind retry.
		result, err = b.call(ctx, path, map[string]string{"task": b.options.Task}, http.StatusCreated, r.RemoteAddr)
		var handle string
		var expires int64
		if err == nil && len(result) == 2 && json.Unmarshal(result["handle"], &handle) == nil && browserHandle.MatchString(handle) && json.Unmarshal(result["expiresAt"], &expires) == nil && expires > time.Now().UnixMilli() {
			b.handle, b.expiresAt, b.uncertain = handle, expires, false
			visibleExpiry := expires
			if b.options.Deadline.UnixMilli() < visibleExpiry {
				visibleExpiry = b.options.Deadline.UnixMilli()
			}
			payload = map[string]any{"ready": true, "expiresAt": visibleExpiry}
			status = http.StatusCreated
		} else {
			err = errBrowserUnavailable
		}
	case "/v1/browser/check":
		var result map[string]json.RawMessage
		result, err = b.call(ctx, path, map[string]string{"handle": b.handle, "action": "check-visible"}, http.StatusOK, r.RemoteAddr)
		var matched bool
		if err == nil && len(result) == 1 && json.Unmarshal(result["matched"], &matched) == nil && string(result["matched"]) != "null" {
			payload = map[string]bool{"matched": matched}
		} else {
			err = errBrowserUnavailable
		}
	case "/v1/browser/close":
		err = b.cleanup(ctx)
		payload = map[string]bool{"closed": true}
	}
	if err != nil {
		_ = b.options.Audit(ctx, path, "failure")
		browserError(w, http.StatusBadGateway)
		return
	}
	if b.allowed(ctx, r.RemoteAddr) != nil {
		b.refuseAndClose()
		browserError(w, http.StatusForbidden)
		return
	}
	if b.options.Audit(ctx, path, "success") != nil {
		b.refuseAndClose()
		browserError(w, http.StatusServiceUnavailable)
		return
	}
	if b.allowed(ctx, r.RemoteAddr) != nil {
		b.refuseAndClose()
		browserError(w, http.StatusForbidden)
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// Close permanently ends admission and attempts broker cleanup. The controller
// must call this on task expiry, pairing loss and shutdown, not just HTTP traffic.
func (b *BrowserRelay) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return b.cleanup(ctx)
}

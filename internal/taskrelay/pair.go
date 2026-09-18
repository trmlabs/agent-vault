package taskrelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errDenied = errors.New("task relay denied")

const apiTimeout = 3 * time.Second
const pairInterval = time.Second

type pairVerifier struct {
	config FixedConfig
	client *http.Client
}

func newPairVerifier(c FixedConfig) (*pairVerifier, error) {
	t, e := clientTLS(c.Kubernetes.CAFile, "")
	if e != nil {
		return nil, e
	}
	return &pairVerifier{c, &http.Client{Timeout: apiTimeout, Transport: &http.Transport{TLSClientConfig: t, Proxy: nil, MaxResponseHeaderBytes: 8192}, CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied }}}, nil
}

// check never consults caller headers. With a nonempty peer it requires the
// socket address to equal the immutable pairing and the current live Pod IP.
func (v *pairVerifier) check(ctx context.Context, peer string) error {
	c := v.config
	if !time.Now().Before(c.Deadline) {
		return errDenied
	}
	if peer != "" {
		host, _, e := net.SplitHostPort(peer)
		if e != nil || !net.ParseIP(host).Equal(net.ParseIP(c.Sandbox.PodIP)) {
			return errDenied
		}
	}
	token, e := readBoundedFile(c.Kubernetes.ReviewerTokenFile, 32<<10)
	if e != nil || strings.TrimSpace(string(token)) == "" {
		return errDenied
	}
	endpoint := strings.TrimRight(c.Kubernetes.APIURL, "/") + "/api/v1/namespaces/" + url.PathEscape(c.Sandbox.Namespace) + "/pods/" + url.PathEscape(c.Sandbox.Name)
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return errDenied
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, e := v.client.Do(req)
	if e != nil {
		return errDenied
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errDenied
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(b) > 65536 {
		return errDenied
	}
	var pod struct {
		Metadata struct {
			Namespace         string  `json:"namespace"`
			Name              string  `json:"name"`
			UID               string  `json:"uid"`
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
			PodIP string `json:"podIP"`
		} `json:"status"`
	}
	if json.Unmarshal(b, &pod) != nil || pod.Metadata.Namespace != c.Sandbox.Namespace || pod.Metadata.Name != c.Sandbox.Name || pod.Metadata.UID != c.Sandbox.UID || pod.Metadata.DeletionTimestamp != nil || pod.Status.Phase != "Running" || !net.ParseIP(pod.Status.PodIP).Equal(net.ParseIP(c.Sandbox.PodIP)) || !time.Now().Before(c.Deadline) {
		return errDenied
	}
	return nil
}

// readProof reads a fresh, trusted projected file on every admission. The local
// claims check only bounds relay lifetime; the broker verifies the signature,
// issuer, TokenReview and relay Pod binding. No caller token is accepted.
func readProof(c UpstreamConfig, deadline time.Time) (string, time.Time, error) {
	if !deadline.After(time.Now()) {
		return "", time.Time{}, errDenied
	}
	token, expiry, e := readProjectedProof(c)
	if e != nil {
		return "", time.Time{}, e
	}
	return token, minTime(deadline, expiry), nil
}

// readProjectedProof also serves trusted browser cleanup after task withdrawal.
// Browser action admission separately enforces the fixed task deadline.
func readProjectedProof(c UpstreamConfig) (string, time.Time, error) {
	b, e := readBoundedFile(c.ProofFile, 32<<10)
	if e != nil {
		return "", time.Time{}, errDenied
	}
	token := strings.TrimSpace(string(b))
	parts := strings.Split(token, ".")
	if len(parts) != 3 || strings.ContainsAny(token, "\r\n\t ") {
		return "", time.Time{}, errDenied
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return "", time.Time{}, errDenied
	}
	var claims struct {
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", time.Time{}, errDenied
	}
	var audience string
	var audiences []string
	if json.Unmarshal(claims.Aud, &audience) != nil {
		if json.Unmarshal(claims.Aud, &audiences) != nil || len(audiences) != 1 {
			return "", time.Time{}, errDenied
		}
		audience = audiences[0]
	}
	expiry := time.Unix(claims.Exp, 0)
	if audience != c.Audience || !expiry.After(time.Now()) {
		return "", time.Time{}, errDenied
	}
	return token, expiry, nil
}

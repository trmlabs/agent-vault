package taskrelay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func (r *relay) connect(w http.ResponseWriter, req *http.Request) {
	if !r.acquire() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer r.release()
	c := r.config.Connect
	if req.Method != http.MethodConnect || req.URL.Host != req.Host || req.RequestURI != req.Host || req.ContentLength != 0 || len(req.TransferEncoding) != 0 || req.URL.User != nil || req.URL.RawQuery != "" {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	allowed := c.Routes == routesBroker && brokerRouteTarget(req.Host)
	for _, target := range c.AllowedTargets {
		if req.Host == target {
			allowed = true
		}
	}
	for h := range req.Header {
		switch h {
		case "User-Agent", "Proxy-Connection":
		case "Connection":
			values := req.Header.Values(h)
			if len(values) != 1 || (!strings.EqualFold(strings.TrimSpace(values[0]), "close") && !strings.EqualFold(strings.TrimSpace(values[0]), "keep-alive")) {
				allowed = false
			}
		default:
			allowed = false
		}
	}
	if !allowed || r.admit(req.Context(), req.RemoteAddr, "connect") != nil {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	defer func() { _ = r.record("connect", "terminal") }()
	proof, expiry, e := readProof(c.Upstream, r.config.Deadline)
	if e != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	dialCtx, cancelDial := context.WithTimeout(req.Context(), r.handshake())
	up, e := dialUpstream(dialCtx, c.Upstream)
	cancelDial()
	if e != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(r.handshake())))
	if !time.Now().Before(expiry) || r.pair.check(req.Context(), req.RemoteAddr) != nil {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	session := readSession(c.Upstream)
	if session != "" {
		session = "Gatehouse-Session: " + session + "\r\n"
	}
	// A shared proxy states which agent Pod is behind this connection.
	attestation, agent, e := r.attest(req.RemoteAddr)
	if e != nil {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if attestation != "" {
		session += brokercore.AttestationHeader + ": " + attestation + "\r\n"
	}
	if _, e = fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n%s\r\n", req.Host, req.Host, proof, session); e != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Bound the entire response header. None of its fields or body reaches the
	// caller, even if a broker error echoes the proof.
	limited := &io.LimitedReader{R: up, N: 8193}
	reader := bufio.NewReader(limited)
	status, e := reader.ReadString('\n')
	if e == nil && !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		// The broker's status (not its text) names the refusal in the relay log.
		if code := strings.TrimPrefix(status, "HTTP/1.1 "); len(code) >= 3 && strings.Trim(code[:3], "0123456789") == "" {
			_ = r.record("connect", "refused:"+code[:3])
		}
	}
	if e == nil && strings.HasPrefix(status, "HTTP/1.1 403 ") {
		// The broker refused the target (not in the catalog, or not this
		// pool's): a refusal, not an outage. Only the status passes.
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if e != nil || !strings.HasPrefix(status, "HTTP/1.1 200 ") || !strings.HasSuffix(status, "\r\n") {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	headers, e := textproto.NewReader(reader).ReadMIMEHeader()
	if e != nil || limited.N <= 0 || len(headers.Values("Content-Length")) > 1 || (headers.Get("Content-Length") != "" && headers.Get("Content-Length") != "0") || len(headers.Values("Transfer-Encoding")) != 0 || r.pair.check(req.Context(), req.RemoteAddr) != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.record("connect", "established") != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, buffer, e := w.(http.Hijacker).Hijack()
	if e != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if _, e = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if buffer.Flush() != nil {
		return
	}
	// Restore the bounded reader after parsing; buffered tunnel bytes are kept.
	limited.N = 1<<63 - 1
	stopWatch := r.watchPeer(req.RemoteAddr, agent, func() { _ = conn.Close(); _ = up.Close() })
	defer stopWatch()
	copyTunnel(r.ctx, conn, buffer, up, reader, expiry)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// readSession reads the runner session token fresh for each connection. It
// returns "" when none is configured or the file holds no single-line token.
func readSession(c UpstreamConfig) string {
	if c.SessionFile == "" {
		return ""
	}
	b, e := readBoundedFile(c.SessionFile, 8<<10) // the broker reads no more
	if e != nil {
		return ""
	}
	token := strings.TrimSpace(string(b))
	if strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n") {
		return ""
	}
	return token
}

var dnsHostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// brokerRouteTarget is the shape a CONNECT target must have to be forwarded
// under broker routing: a lower-case DNS name of two or more labels, its last
// label not all digits (so no IPv4 literal; an IPv6 literal fails the
// labels), and port 443 only. Whether the host is reachable is the broker's
// catalog's decision.
func brokerRouteTarget(target string) bool {
	host, port, e := net.SplitHostPort(target)
	if e != nil || port != "443" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !dnsHostLabel.MatchString(label) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

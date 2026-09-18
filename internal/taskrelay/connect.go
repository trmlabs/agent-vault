package taskrelay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"time"
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
	allowed := false
	for _, target := range c.AllowedTargets {
		if req.Host == target {
			allowed = true
		}
	}
	for h := range req.Header {
		switch h {
		case "User-Agent", "Proxy-Connection":
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
	up, e := dialUpstream(req.Context(), c.Upstream)
	if e != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(handshakeTimeout)))
	if _, e = fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n", req.Host, req.Host, proof); e != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Bound the entire response header. None of its fields or body reaches the
	// caller, even if a broker error echoes the proof.
	limited := &io.LimitedReader{R: up, N: 8193}
	reader := bufio.NewReader(limited)
	status, e := reader.ReadString('\n')
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
	copyTunnel(r.ctx, conn, buffer, up, reader, expiry)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

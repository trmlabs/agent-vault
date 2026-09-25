package taskrelay

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestConnectStandardConnectionHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, target, headers string
		allowed               bool
	}{
		{"absent", "approved.test:443", "", true},
		{"keep-alive", "approved.test:443", "Connection: keep-alive\r\n", true},
		{"close", "approved.test:443", "Connection: close\r\n", true},
		{"case-insensitive", "approved.test:443", "Connection: Keep-Alive\r\n", true},
		{"upgrade", "approved.test:443", "Connection: upgrade\r\n", false},
		{"nominated-header", "approved.test:443", "Connection: keep-alive, Proxy-Authorization\r\n", false},
		{"duplicate", "approved.test:443", "Connection: close\r\nConnection: keep-alive\r\n", false},
		{"empty", "approved.test:443", "Connection:\r\n", false},
		{"caller-proof", "approved.test:443", "Connection: keep-alive\r\nProxy-Authorization: Bearer caller\r\n", false},
		{"wrong-target", "forbidden.test:443", "Connection: keep-alive\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t)
			var arrivals atomic.Int32
			var leaked atomic.Bool
			broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				arrivals.Add(1)
				if req.Header.Get("Connection") != "" || req.Header.Get("Proxy-Connection") != "" || req.Header.Get("Proxy-Authorization") == "" {
					leaked.Store(true)
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
				_ = rw.Flush()
				_, _ = io.Copy(conn, rw)
			}))
			broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.cert}}
			broker.StartTLS()
			defer broker.Close()
			f.c.Connect = &ConnectConfig{Listen: freeAddress(t), Upstream: f.upstream(t, broker.Listener.Addr().String()), AllowedTargets: []string{"approved.test:443"}}
			f.start(t)
			conn := f.dial(t, f.c.Connect.Listen)
			defer conn.Close()
			_, _ = io.WriteString(conn, "CONNECT "+tc.target+" HTTP/1.1\r\nHost: "+tc.target+"\r\n"+tc.headers+"\r\n")
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if !tc.allowed {
				if response.StatusCode != http.StatusForbidden || arrivals.Load() != 0 {
					t.Fatal("unsupported CONNECT reached broker")
				}
				return
			}
			if response.StatusCode != http.StatusOK || arrivals.Load() != 1 || leaked.Load() {
				t.Fatal("standard CONNECT header was refused or forwarded")
			}
			_, _ = io.WriteString(conn, "ping")
			body := make([]byte, 4)
			if _, err := io.ReadFull(reader, body); err != nil || string(body) != "ping" {
				t.Fatal("admitted tunnel did not relay")
			}
		})
	}
}

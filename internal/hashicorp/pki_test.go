package hashicorp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignCertificateUsesTheRoleAndReturnsTheChain(t *testing.T) {
	for name, data := range map[string]map[string]any{
		"ca chain":   {"certificate": "LEAF", "ca_chain": []string{"INTERMEDIATE", "ROOT"}},
		"issuing ca": {"certificate": "LEAF", "issuing_ca": "ROOT"},
	} {
		var got map[string]interface{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/pki-gatehouse-proxy/sign/proxy" {
				t.Errorf("%s: path %s", name, r.URL.Path)
			}
			got = decodeBody(t, r)
			writeJSON(w, map[string]any{"data": data})
		}))
		cert, chain, err := newClientForServer(t, srv.URL).SignCertificate(context.Background(), "pki-gatehouse-proxy", "proxy", "CSR",
			[]string{"a.svc.cluster.local", "a.svc"}, 24*time.Hour)
		srv.Close()
		if err != nil || cert != "LEAF\n" || chain == "" {
			t.Fatalf("%s: %q %q %v", name, cert, chain, err)
		}
		if got["csr"] != "CSR" || got["common_name"] != "a.svc.cluster.local" || got["alt_names"] != "a.svc" || got["ttl"] != "24h0m0s" {
			t.Errorf("%s: request %v", name, got)
		}
	}
	c := newClientForServer(t, "http://127.0.0.1:1")
	for name, call := range map[string]func() error{
		"traversal mount": func() error {
			_, _, err := c.SignCertificate(context.Background(), "../sys", "proxy", "CSR", []string{"a"}, time.Hour)
			return err
		},
		"no names": func() error {
			_, _, err := c.SignCertificate(context.Background(), "pki", "proxy", "CSR", nil, time.Hour)
			return err
		},
		"TTL over a day": func() error {
			_, _, err := c.SignCertificate(context.Background(), "pki", "proxy", "CSR", []string{"a"}, 48*time.Hour)
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

package proxyactivity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// fakeProxies admits two proxy bindings by token.
type fakeProxies map[string]Identity

func (f fakeProxies) IdentifyProxy(_ context.Context, token string, _ netip.Addr) (Identity, error) {
	if id, ok := f[token]; ok {
		return id, nil
	}
	return Identity{}, errors.New("not a proxy")
}

func newService(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Service{Store: db, Retention: 24 * time.Hour, Identifier: fakeProxies{
		"developers-proxy": {Scope: "td/gatehouse-proxy/uid-1", Namespaces: []string{"developers"}},
		"customers-proxy":  {Scope: "td/customer-proxy/uid-2", Namespaces: []string{"customers"}},
	}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	return s, mux
}

func call(h http.Handler, token, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.RemoteAddr = "10.200.0.7:40000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func readAll(t *testing.T, h http.Handler, token string) map[string]Row {
	t.Helper()
	out := map[string]Row{}
	for after := ""; ; {
		w := call(h, token, ReadPath, ReadRequest{After: after})
		var page ReadResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.RetentionSeconds != 86400 {
			t.Fatalf("read: %d %s", w.Code, w.Body)
		}
		for _, r := range page.Sandboxes {
			out[r.OwnerUID] = r
		}
		if after = page.Next; after == "" {
			return out
		}
	}
}

// A proxy writes and reads only its own binding's Sandboxes, in its own
// namespaces; the view pages through thousands and keeps the latest time.
func TestProxyActivityIsPerBinding(t *testing.T) {
	_, h := newService(t)
	now := time.Now().Truncate(time.Millisecond).UTC()
	var rows []Row
	for i := 0; i < 4500; i++ {
		rows = append(rows, Row{Namespace: "developers", OwnerUID: fmt.Sprintf("sb-%05d", i), LastSeen: now.Add(-time.Duration(i) * time.Second)})
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: rows}); w.Code != 200 {
		t.Fatalf("record: %d", w.Code)
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: []Row{{Namespace: "developers", OwnerUID: "sb-00009", LastSeen: now.Add(-time.Hour)}}}); w.Code != 200 {
		t.Fatalf("older record: %d", w.Code)
	}
	if w := call(h, "customers-proxy", RecordPath, RecordRequest{Sandboxes: []Row{{Namespace: "customers", OwnerUID: "sb-c", LastSeen: now}}}); w.Code != 200 {
		t.Fatalf("customer record: %d", w.Code)
	}
	developers := readAll(t, h, "developers-proxy")
	if len(developers) != 4500 || !developers["sb-00009"].LastSeen.Equal(now.Add(-9*time.Second)) {
		t.Fatalf("developers' view: %d rows, sb-00009 %v", len(developers), developers["sb-00009"].LastSeen)
	}
	if customers := readAll(t, h, "customers-proxy"); len(customers) != 1 || customers["sb-c"].Namespace != "customers" {
		t.Fatalf("customers' view: %v", customers)
	}
}

// Anything but a proxy, a row outside its namespaces, a malformed row, a
// time from the future or an oversized report is refused, and nothing is
// written.
func TestProxyActivityRefusals(t *testing.T) {
	_, h := newService(t)
	now := time.Now()
	good := Row{Namespace: "developers", OwnerUID: "sb-1", LastSeen: now}
	many := make([]Row, MaxRecordRows+1)
	for i := range many {
		many[i] = Row{Namespace: "developers", OwnerUID: fmt.Sprintf("sb-%d", i), LastSeen: now}
	}
	for name, tc := range map[string]struct {
		token string
		body  any
		code  int
	}{
		"no token":          {"", RecordRequest{Sandboxes: []Row{good}}, 401},
		"not a proxy":       {"worker-token", RecordRequest{Sandboxes: []Row{good}}, 403},
		"another namespace": {"developers-proxy", RecordRequest{Sandboxes: []Row{{Namespace: "customers", OwnerUID: "sb-1", LastSeen: now}}}, 400},
		"bad owner":         {"developers-proxy", RecordRequest{Sandboxes: []Row{{Namespace: "developers", OwnerUID: "../x", LastSeen: now}}}, 400},
		"no time":           {"developers-proxy", RecordRequest{Sandboxes: []Row{{Namespace: "developers", OwnerUID: "sb-1"}}}, 400},
		"future time":       {"developers-proxy", RecordRequest{Sandboxes: []Row{{Namespace: "developers", OwnerUID: "sb-1", LastSeen: now.Add(time.Hour)}}}, 400},
		"too many rows":     {"developers-proxy", RecordRequest{Sandboxes: many}, 400},
		"unknown field":     {"developers-proxy", map[string]any{"sandboxes": []Row{good}, "scope": "td/customer-proxy/uid-2"}, 400},
	} {
		if w := call(h, tc.token, RecordPath, tc.body); w.Code != tc.code {
			t.Errorf("%s: %d, want %d", name, w.Code, tc.code)
		}
	}
	if w := call(h, "worker-token", ReadPath, ReadRequest{}); w.Code != 403 {
		t.Errorf("read by a non-proxy: %d", w.Code)
	}
	if w := call(h, "developers-proxy", ReadPath, ReadRequest{After: "a b"}); w.Code != 400 {
		t.Errorf("bad cursor: %d", w.Code)
	}
	if rows := readAll(t, h, "developers-proxy"); len(rows) != 0 {
		t.Fatalf("a refused report wrote %d rows", len(rows))
	}
}

func TestProxyActivityValidation(t *testing.T) {
	s, _ := newService(t)
	for _, retention := range []time.Duration{time.Minute, 400 * 24 * time.Hour} {
		c := &Service{Store: s.Store, Identifier: s.Identifier, Retention: retention}
		if c.Validate() == nil {
			t.Errorf("retention %v accepted", retention)
		}
	}
	if err := (&Service{Store: s.Store, Identifier: s.Identifier, Retention: time.Hour, MaxRows: -1}).Validate(); err == nil {
		t.Error("negative row ceiling accepted")
	}
	c := &Service{Identifier: s.Identifier, Retention: time.Hour}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "shared store") {
		t.Errorf("no store: %v", err)
	}
}

// A binding's history starts at its first report, empty or not, and the read
// returns it; a report past the binding's row ceiling is refused whole.
func TestProxyActivityHistoryAndCeiling(t *testing.T) {
	s, h := newService(t)
	s.MaxRows = 2
	page := func() ReadResponse {
		var out ReadResponse
		w := call(h, "developers-proxy", ReadPath, ReadRequest{})
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("read: %d", w.Code)
		}
		return out
	}
	if first := page(); first.HistoryStarted != nil {
		t.Fatalf("history before any report: %v", first.HistoryStarted)
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: []Row{}}); w.Code != 200 {
		t.Fatalf("empty report: %d", w.Code)
	}
	started := page().HistoryStarted
	if started == nil || time.Since(*started) > time.Minute {
		t.Fatalf("history after an empty report: %v", started)
	}
	now := time.Now()
	two := []Row{{Namespace: "developers", OwnerUID: "sb-1", LastSeen: now}, {Namespace: "developers", OwnerUID: "sb-2", LastSeen: now}}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: two}); w.Code != 200 {
		t.Fatalf("two rows: %d", w.Code)
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: []Row{{Namespace: "developers", OwnerUID: "sb-3", LastSeen: now}}}); w.Code != http.StatusInsufficientStorage {
		t.Fatalf("a row past the ceiling: %d", w.Code)
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: two}); w.Code != 200 {
		t.Fatalf("updates at the ceiling: %d", w.Code)
	}
	if again := page(); again.HistoryStarted == nil || !again.HistoryStarted.Equal(*started) || len(again.Sandboxes) != 2 {
		t.Fatalf("after the ceiling: %+v", again)
	}
}

// A report is acknowledged with the binding's next sequence; one carrying an
// acknowledged sequence the store no longer reaches is a loss, and the read
// gives the current sequence.
func TestProxyActivitySequenceOnTheWire(t *testing.T) {
	_, h := newService(t)
	row := []Row{{Namespace: "developers", OwnerUID: "sb-1", LastSeen: time.Now()}}
	answer := func(acked int64) RecordResponse {
		t.Helper()
		w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: row, AckedSeq: acked})
		var out RecordResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("record: %d %s", w.Code, w.Body)
		}
		return out
	}
	if a := answer(0); a.Seq != 1 || a.Lost {
		t.Fatalf("first: %+v", a)
	}
	if a := answer(1); a.Seq != 2 || a.Lost {
		t.Fatalf("second: %+v", a)
	}
	if a := answer(7); !a.Lost {
		t.Fatalf("an acknowledgment the store does not reach: %+v", a)
	}
	var page ReadResponse
	w := call(h, "developers-proxy", ReadPath, ReadRequest{})
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Seq != 3 {
		t.Fatalf("read sequence: %s", w.Body)
	}
	if w := call(h, "developers-proxy", RecordPath, RecordRequest{Sandboxes: row, AckedSeq: -1}); w.Code != 400 {
		t.Fatalf("negative acknowledgment: %d", w.Code)
	}
}

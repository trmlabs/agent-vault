package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestProxyActivity(t *testing.T) { checkProxyActivity(t, openTestDB(t)) }

// The latest time wins, a scope reads only its own rows, paging walks every
// row once, and pruning drops only old rows.
func checkProxyActivity(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	scope := fmt.Sprintf("td/gatehouse-proxy/%d", time.Now().UnixNano())
	now := time.Now().Truncate(time.Millisecond).UTC()
	var rows []ProxyActivity
	for i := 0; i < 1200; i++ {
		rows = append(rows, ProxyActivity{Namespace: "developers", OwnerUID: fmt.Sprintf("sb-%05d", i), LastSeen: now.Add(-time.Duration(i) * time.Minute)})
	}
	rows = append(rows, ProxyActivity{Namespace: "developers", OwnerUID: "sb-00001", LastSeen: now}) // repeated in one batch: latest wins
	if err := s.RecordProxyActivity(ctx, scope, rows, 100000); err != nil {
		t.Fatal(err)
	}
	// An older report never moves a time back; a newer one moves it forward.
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{{Namespace: "developers", OwnerUID: "sb-00000", LastSeen: now.Add(-time.Hour)},
		{Namespace: "developers", OwnerUID: "sb-00002", LastSeen: now.Add(time.Second)}}, 100000); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordProxyActivity(ctx, scope+"-other", []ProxyActivity{{Namespace: "customers", OwnerUID: "sb-x", LastSeen: now}}, 100000); err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Time{}
	for after := ""; ; {
		page, err := s.ReadProxyActivity(ctx, scope, after, now.Add(-24*time.Hour), 250)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			if _, dup := got[r.OwnerUID]; dup || r.Namespace != "developers" {
				t.Fatalf("row %+v repeated or foreign", r)
			}
			got[r.OwnerUID] = r.LastSeen
		}
		after = page[len(page)-1].OwnerUID
	}
	if len(got) != 1200 || !got["sb-00000"].Equal(now) || !got["sb-00001"].Equal(now) || !got["sb-00002"].Equal(now.Add(time.Second)) ||
		!got["sb-01199"].Equal(now.Add(-1199*time.Minute)) {
		t.Fatalf("read %d rows: %v %v %v", len(got), got["sb-00000"], got["sb-00001"], got["sb-00002"])
	}
	if recent, err := s.ReadProxyActivity(ctx, scope, "", now.Add(-10*time.Minute), 5000); err != nil || len(recent) != 11 {
		t.Fatalf("since filter: %d %v", len(recent), err)
	}
	if err := s.PruneProxyActivity(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if kept, err := s.ReadProxyActivity(ctx, scope, "", time.Time{}, 5000); err != nil || len(kept) != 61 {
		t.Fatalf("after pruning: %d %v", len(kept), err)
	}
	if err := s.RecordProxyActivity(ctx, "", rows[:1], 100000); err == nil {
		t.Fatal("no scope accepted")
	}
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{{OwnerUID: "sb"}}, 100000); err == nil {
		t.Fatal("row with no namespace accepted")
	}
}

func TestProxyActivityHistoryAndCeiling(t *testing.T) {
	checkProxyActivityHistoryAndCeiling(t, openTestDB(t))
}

// A scope's history starts at its first report, even an empty one, and does
// not move; a report that would take a scope past its row ceiling is refused
// whole, while updates to rows it holds still land.
func checkProxyActivityHistoryAndCeiling(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	scope := fmt.Sprintf("td/gatehouse-proxy/history-%d", time.Now().UnixNano())
	if _, known, err := s.ProxyActivityHistory(ctx, scope); err != nil || known {
		t.Fatalf("history before any report: %v %v", known, err)
	}
	before := time.Now().Add(-time.Second)
	if err := s.RecordProxyActivity(ctx, scope, nil, 3); err != nil {
		t.Fatal(err)
	}
	started, known, err := s.ProxyActivityHistory(ctx, scope)
	if err != nil || !known || started.Before(before) || started.After(time.Now().Add(time.Second)) {
		t.Fatalf("history after an empty report: %v %v %v", started, known, err)
	}
	now := time.Now().Truncate(time.Millisecond).UTC()
	row := func(owner string) ProxyActivity {
		return ProxyActivity{Namespace: "developers", OwnerUID: owner, LastSeen: now}
	}
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{row("a"), row("b"), row("c")}, 3); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{row("a"), row("d")}, 3); !errors.Is(err, ErrProxyActivityFull) {
		t.Fatalf("a fourth row: %v", err)
	}
	later := row("a")
	later.LastSeen = now.Add(time.Minute)
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{later, row("b")}, 3); err != nil {
		t.Fatalf("updates at the ceiling: %v", err)
	}
	rows, err := s.ReadProxyActivity(ctx, scope, "", time.Time{}, 10)
	if err != nil || len(rows) != 3 || !rows[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("rows at the ceiling: %+v %v", rows, err)
	}
	if again, _, _ := s.ProxyActivityHistory(ctx, scope); !again.Equal(started) {
		t.Fatalf("history moved: %v then %v", started, again)
	}
	// Pruning every row keeps the history's start.
	if err := s.PruneProxyActivity(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, known, _ := s.ProxyActivityHistory(ctx, scope); !known || !again.Equal(started) {
		t.Fatalf("history lost with its rows: %v %v", again, known)
	}
}

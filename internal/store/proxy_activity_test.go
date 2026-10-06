package store

import (
	"context"
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
	if err := s.RecordProxyActivity(ctx, scope, rows); err != nil {
		t.Fatal(err)
	}
	// An older report never moves a time back; a newer one moves it forward.
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{{Namespace: "developers", OwnerUID: "sb-00000", LastSeen: now.Add(-time.Hour)},
		{Namespace: "developers", OwnerUID: "sb-00002", LastSeen: now.Add(time.Second)}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordProxyActivity(ctx, scope+"-other", []ProxyActivity{{Namespace: "customers", OwnerUID: "sb-x", LastSeen: now}}); err != nil {
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
	if err := s.RecordProxyActivity(ctx, "", rows[:1]); err == nil {
		t.Fatal("no scope accepted")
	}
	if err := s.RecordProxyActivity(ctx, scope, []ProxyActivity{{OwnerUID: "sb"}}); err == nil {
		t.Fatal("row with no namespace accepted")
	}
}

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
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", rows, 100000, 100, 0); err != nil {
		t.Fatal(err)
	}
	// An older report never moves a time back; a newer one moves it forward.
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", []ProxyActivity{{Namespace: "developers", OwnerUID: "sb-00000", LastSeen: now.Add(-time.Hour)},
		{Namespace: "developers", OwnerUID: "sb-00002", LastSeen: now.Add(time.Second)}}, 100000, 100, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope+"-other", "r1", []ProxyActivity{{Namespace: "customers", OwnerUID: "sb-x", LastSeen: now}}, 100000, 100, 0); err != nil {
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
	if err := s.PruneProxyActivity(ctx, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if kept, err := s.ReadProxyActivity(ctx, scope, "", time.Time{}, 5000); err != nil || len(kept) != 61 {
		t.Fatalf("after pruning: %d %v", len(kept), err)
	}
	if _, _, err := s.RecordProxyActivity(ctx, "", "r1", rows[:1], 100000, 100, 0); err == nil {
		t.Fatal("no scope accepted")
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", []ProxyActivity{{OwnerUID: "sb"}}, 100000, 100, 0); err == nil {
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
	if _, _, known, err := s.ProxyActivityHistory(ctx, scope); err != nil || known {
		t.Fatalf("history before any report: %v %v", known, err)
	}
	before := time.Now().Add(-time.Second)
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", nil, 3, 100, 0); err != nil {
		t.Fatal(err)
	}
	started, _, known, err := s.ProxyActivityHistory(ctx, scope)
	if err != nil || !known || started.Before(before) || started.After(time.Now().Add(time.Second)) {
		t.Fatalf("history after an empty report: %v %v %v", started, known, err)
	}
	now := time.Now().Truncate(time.Millisecond).UTC()
	row := func(owner string) ProxyActivity {
		return ProxyActivity{Namespace: "developers", OwnerUID: owner, LastSeen: now}
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", []ProxyActivity{row("a"), row("b"), row("c")}, 3, 100, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", []ProxyActivity{row("a"), row("d")}, 3, 100, 0); !errors.Is(err, ErrProxyActivityFull) {
		t.Fatalf("a fourth row: %v", err)
	}
	later := row("a")
	later.LastSeen = now.Add(time.Minute)
	if _, _, err := s.RecordProxyActivity(ctx, scope, "r1", []ProxyActivity{later, row("b")}, 3, 100, 0); err != nil {
		t.Fatalf("updates at the ceiling: %v", err)
	}
	rows, err := s.ReadProxyActivity(ctx, scope, "", time.Time{}, 10)
	if err != nil || len(rows) != 3 || !rows[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("rows at the ceiling: %+v %v", rows, err)
	}
	if again, _, _, _ := s.ProxyActivityHistory(ctx, scope); !again.Equal(started) {
		t.Fatalf("history moved: %v then %v", started, again)
	}
	// Pruning every row keeps the history's start.
	if err := s.PruneProxyActivity(ctx, now.Add(time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, _, known, _ := s.ProxyActivityHistory(ctx, scope); !known || !again.Equal(started) {
		t.Fatalf("history lost with its rows: %v %v", again, known)
	}
}

func TestProxyActivitySequence(t *testing.T) { checkProxyActivitySequence(t, openTestDB(t)) }

// Each accepted report takes its replica stream's next sequence. A report
// carrying an acknowledged sequence its stream no longer reaches (a
// restore), or one for a stream the store lost, is a loss and restarts the
// history; one its stream still reaches, as after a broker restart with
// nothing lost, changes nothing. Another replica's reports never advance a
// stream, so a busy replica cannot overtake an idle one's loss.
func checkProxyActivitySequence(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	scope := fmt.Sprintf("td/gatehouse-proxy/seq-%d", time.Now().UnixNano())
	row := []ProxyActivity{{Namespace: "developers", OwnerUID: "sb-1", LastSeen: time.Now()}}
	record := func(replica string, acked int64) (int64, bool) {
		t.Helper()
		seq, lost, err := s.RecordProxyActivity(ctx, scope, replica, row, 100, 100, acked)
		if err != nil {
			t.Fatal(err)
		}
		return seq, lost
	}
	exec := func(query string) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(query), scope); err != nil {
			t.Fatal(err)
		}
	}
	history := func() time.Time {
		t.Helper()
		started, _, _, err := s.ProxyActivityHistory(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return started
	}
	if seq, lost := record("aaaa0001", 0); seq != 1 || lost {
		t.Fatalf("first report: %d %v", seq, lost)
	}
	if seq, lost := record("aaaa0001", 1); seq != 2 || lost {
		t.Fatalf("second report: %d %v", seq, lost)
	}
	if seq, lost := record("bbbb0002", 0); seq != 1 || lost {
		t.Fatalf("another replica's own stream: %d %v", seq, lost)
	}
	exec(`UPDATE proxy_activity_scope SET history_started_ms = history_started_ms - 7200000 WHERE scope = ?`)
	old := history()
	// A broker restart loses nothing: the streams live in the database.
	if seq, lost := record("aaaa0001", 2); seq != 3 || lost || !history().Equal(old) {
		t.Fatalf("after a broker restart: %d %v", seq, lost)
	}
	// A restore to when replica A's stream stood at 1 and B's at 0. B is busy
	// and reports ten times before A reports again: it cannot overtake A's
	// loss, since it advances only its own stream.
	exec(`UPDATE proxy_activity_stream SET seq = 1 WHERE scope = ? AND replica = 'aaaa0001'`)
	exec(`DELETE FROM proxy_activity_stream WHERE scope = ? AND replica = 'bbbb0002'`)
	acked := int64(0)
	for i := 0; i < 10; i++ {
		seq, _ := record("bbbb0002", acked)
		acked = seq
	}
	if !history().Equal(old) {
		t.Fatal("B's reports, with nothing B saw lost, moved the history")
	}
	_, streams, _, _ := s.ProxyActivityHistory(ctx, scope)
	if streams["aaaa0001"] != 1 || streams["bbbb0002"] != 10 {
		t.Fatalf("streams %v", streams)
	}
	before := time.Now().Add(-time.Second)
	if seq, lost := record("aaaa0001", 3); seq != 2 || !lost {
		t.Fatalf("A after the restore: %d %v, want a loss", seq, lost)
	}
	if restarted := history(); restarted.Before(before) {
		t.Fatalf("the history did not restart: %v", restarted)
	}
	// A stream the store lost entirely while its replica holds an
	// acknowledgment.
	exec(`DELETE FROM proxy_activity_stream WHERE scope = ? AND replica = 'bbbb0002'`)
	if seq, lost := record("bbbb0002", 10); seq != 1 || !lost {
		t.Fatalf("stream lost: %d %v, want a loss", seq, lost)
	}
	// A refused report changes nothing, not even the stream.
	if _, _, err := s.RecordProxyActivity(ctx, scope, "aaaa0001", []ProxyActivity{{Namespace: "developers", OwnerUID: "sb-2", LastSeen: time.Now()}}, 1, 100, 2); !errors.Is(err, ErrProxyActivityFull) {
		t.Fatalf("over the ceiling: %v", err)
	}
	if _, streams, _, _ := s.ProxyActivityHistory(ctx, scope); streams["aaaa0001"] != 2 {
		t.Fatalf("a refused report moved the stream to %d", streams["aaaa0001"])
	}
	// Streams are pruned on their own cutoff, not the rows'.
	if err := s.PruneProxyActivity(ctx, time.Now().Add(time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, streams, _, _ := s.ProxyActivityHistory(ctx, scope); len(streams) != 2 {
		t.Fatalf("streams pruned with the rows: %v", streams)
	}
	if err := s.PruneProxyActivity(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, streams, _, _ := s.ProxyActivityHistory(ctx, scope); len(streams) != 0 {
		t.Fatalf("streams after pruning: %v", streams)
	}
}

func TestProxyActivityStreamCeiling(t *testing.T) { checkProxyActivityStreamCeiling(t, openTestDB(t)) }

// A binding starts at most maxStreams replica streams: a report that would
// start one more is refused whole and writes nothing, while the streams it
// holds go on reporting, and another binding is not affected.
func checkProxyActivityStreamCeiling(t *testing.T, s *SQLStore) {
	ctx := context.Background()
	scope := "td/stream-ceiling/" + time.Now().Format("150405.000000000")
	row := func(owner string) []ProxyActivity {
		return []ProxyActivity{{Namespace: "developers", OwnerUID: owner, LastSeen: time.Now()}}
	}
	for _, replica := range []string{"aaaa0001", "bbbb0002"} {
		if _, _, err := s.RecordProxyActivity(ctx, scope, replica, row("sb-"+replica), 100, 2, 0); err != nil {
			t.Fatalf("%s: %v", replica, err)
		}
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope, "cccc0003", row("sb-new"), 100, 2, 0); !errors.Is(err, ErrProxyActivityStreams) {
		t.Fatalf("a stream past the ceiling: %v", err)
	}
	_, streams, _, _ := s.ProxyActivityHistory(ctx, scope)
	got, _ := s.ReadProxyActivity(ctx, scope, "", time.Time{}, 100)
	if len(streams) != 2 || len(got) != 2 {
		t.Fatalf("a refused stream wrote: streams %v, rows %d", streams, len(got))
	}
	if seq, _, err := s.RecordProxyActivity(ctx, scope, "aaaa0001", row("sb-aaaa0001"), 100, 2, 1); err != nil || seq != 2 {
		t.Fatalf("a held stream at the ceiling: %d %v", seq, err)
	}
	if _, _, err := s.RecordProxyActivity(ctx, scope+"-other", "cccc0003", row("sb-x"), 100, 2, 0); err != nil {
		t.Fatalf("another binding: %v", err)
	}
}

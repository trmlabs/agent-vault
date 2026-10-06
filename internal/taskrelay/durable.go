package taskrelay

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// DurableActivityConfig, in shared mode with adminListen, keeps activity in
// the broker's shared store so it outlives this replica. Every PushSeconds
// (default 15) the replica reports its Sandboxes' newer last-seen times, if
// any, and once more on shutdown; the activity report then merges the broker's view of
// every replica, past and present, with this replica's own. Both calls go over
// the CONNECT upstream, as the proxy itself.
type DurableActivityConfig struct {
	PushSeconds int64 `json:"pushSeconds,omitempty"`
}

const (
	activityRecordPath = "/v1/proxy/activity"
	activityReadPath   = "/v1/proxy/activity/read"
	// activityRecordRows is the broker's limit on one report.
	activityRecordRows = 5000
	// finalPushTimeout bounds the report sent on shutdown.
	finalPushTimeout = 5 * time.Second
)

func (d *DurableActivityConfig) interval() time.Duration {
	if d.PushSeconds == 0 {
		return 15 * time.Second
	}
	return time.Duration(d.PushSeconds) * time.Second
}

// durable reports to and reads from the broker's shared store.
type durable struct {
	activity *activity
	upstream UpstreamConfig
	interval time.Duration

	mu sync.Mutex
	// acked is the binding sequence the broker last acknowledged to this
	// replica (0 until its first accepted report); firstAcked is when that
	// first acknowledgment came. A replica with no acknowledgment cannot
	// vouch that the broker's history is whole, so the janitor holds while
	// no live replica has one older than its idle window.
	acked      int64
	firstAcked time.Time
}

// verification is this replica's acknowledged sequence and when it first got
// one, for its activity report.
func (d *durable) verification() (int64, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acked, d.firstAcked
}

// run reports every interval until ctx ends, then once more. It sends
// nothing when nothing is new.
func (d *durable) run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), finalPushTimeout)
			_ = d.push(final)
			cancel()
			return
		case <-ticker.C:
			_ = d.push(ctx)
		}
	}
}

// push reports every Sandbox whose last use is newer than what the broker
// last accepted from this replica, with the sequence last acknowledged. If
// the broker says it lost acknowledged writes, every entry this replica holds
// is marked to report again: at most its retained entries, once per loss. A
// failed report is retried next time.
func (d *durable) push(ctx context.Context) error {
	rows := d.activity.pending()
	for start := 0; start < len(rows); start += activityRecordRows {
		chunk := rows[start:min(start+activityRecordRows, len(rows))]
		acked, _ := d.verification()
		body, e := json.Marshal(map[string]any{"sandboxes": chunk, "ackedSeq": acked})
		if e != nil {
			return e
		}
		status, b, e := brokerPost(ctx, d.upstream, activityRecordPath, body, 4096)
		if e != nil {
			return e
		}
		var answer struct {
			Seq  int64 `json:"seq"`
			Lost bool  `json:"lost"`
		}
		if status != http.StatusOK || json.Unmarshal(b, &answer) != nil || answer.Seq <= 0 {
			return errDenied
		}
		d.activity.accepted(chunk)
		d.mu.Lock()
		d.acked = answer.Seq
		if d.firstAcked.IsZero() {
			d.firstAcked = time.Now()
		}
		d.mu.Unlock()
		if answer.Lost {
			// What this replica holds goes back on the next report.
			d.activity.repushAll()
			return nil
		}
	}
	return nil
}

// durableView is the broker's whole view for this proxy's binding.
type durableView struct {
	sandboxes []SandboxActivity
	retention int64
	// historyStarted is when the binding's history began; zero if none.
	historyStarted time.Time
	// seq is the binding's current sequence.
	seq int64
}

// read returns the broker's whole view for this proxy's binding.
func (d *durable) read(ctx context.Context) (durableView, error) {
	var view durableView
	for after := ""; ; {
		body, _ := json.Marshal(map[string]string{"after": after})
		status, b, e := brokerPost(ctx, d.upstream, activityReadPath, body, 64<<20)
		if e != nil {
			return view, e
		}
		var page struct {
			RetentionSeconds int64             `json:"retentionSeconds"`
			HistoryStarted   *time.Time        `json:"historyStarted"`
			Seq              int64             `json:"seq"`
			Sandboxes        []SandboxActivity `json:"sandboxes"`
			Next             string            `json:"next"`
		}
		if status != http.StatusOK || json.Unmarshal(b, &page) != nil || page.RetentionSeconds <= 0 || (page.Next != "" && page.Next <= after) {
			return view, errDenied
		}
		if after == "" {
			view.seq = page.Seq
			if page.HistoryStarted != nil {
				view.historyStarted = page.HistoryStarted.UTC()
			}
		}
		view.sandboxes, view.retention = append(view.sandboxes, page.Sandboxes...), page.RetentionSeconds
		if after = page.Next; after == "" {
			return view, nil
		}
	}
}

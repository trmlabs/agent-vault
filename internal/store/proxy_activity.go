package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProxyActivity is one Sandbox's latest use through a proxy binding.
type ProxyActivity struct {
	Namespace string
	OwnerUID  string
	LastSeen  time.Time
}

// proxyActivityChunk keeps one statement's parameters well under SQLite's
// limit.
const proxyActivityChunk = 500

// ErrProxyActivityFull refuses a report that would take a scope past its row
// ceiling.
var ErrProxyActivityFull = errors.New("proxy activity: the scope is at its row ceiling")

// RecordProxyActivity keeps, per Sandbox, the latest of the stored and the
// reported times. A row repeated within rows keeps its latest time. The
// scope's history starts at its first report. A report that would take the
// scope past maxRows rows is refused whole with ErrProxyActivityFull; rows
// already held may still be updated by a report that adds none.
func (s *SQLStore) RecordProxyActivity(ctx context.Context, scope string, rows []ProxyActivity, maxRows int) error {
	if scope == "" {
		return fmt.Errorf("proxy activity needs a scope")
	}
	latest := make(map[string]ProxyActivity, len(rows))
	for _, r := range rows {
		if r.OwnerUID == "" || r.Namespace == "" {
			return fmt.Errorf("proxy activity row needs a namespace and a Sandbox UID")
		}
		if have, ok := latest[r.OwnerUID]; !ok || r.LastSeen.After(have.LastSeen) {
			latest[r.OwnerUID] = r
		}
	}
	unique := make([]ProxyActivity, 0, len(latest))
	for _, r := range latest {
		unique = append(unique, r)
	}
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO proxy_activity_scope (scope, history_started_ms) VALUES (?, `+s.dbNowMs()+`)
		ON CONFLICT (scope) DO NOTHING`), scope); err != nil { // #nosec G202 -- constant clock expression
		return err
	}
	if err := s.proxyActivityRoom(ctx, scope, unique, maxRows); err != nil {
		return err
	}
	for start := 0; start < len(unique); start += proxyActivityChunk {
		chunk := unique[start:min(start+proxyActivityChunk, len(unique))]
		values := make([]string, len(chunk))
		args := make([]any, 0, 4*len(chunk))
		for i, r := range chunk {
			values[i] = "(?, ?, ?, ?)"
			args = append(args, scope, r.OwnerUID, r.Namespace, r.LastSeen.UnixMilli())
		}
		query := `INSERT INTO proxy_activity (scope, owner_uid, namespace, last_seen_ms) VALUES ` + strings.Join(values, ", ") + `
			ON CONFLICT (scope, owner_uid) DO UPDATE SET namespace = excluded.namespace, last_seen_ms =
			CASE WHEN excluded.last_seen_ms > proxy_activity.last_seen_ms THEN excluded.last_seen_ms ELSE proxy_activity.last_seen_ms END`
		if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(query), args...); err != nil { // #nosec G202 -- placeholders only
			return err
		}
	}
	return nil
}

// ReadProxyActivity returns up to limit of a scope's rows seen at or after
// since, in Sandbox UID order after the cursor after.
func (s *SQLStore) ReadProxyActivity(ctx context.Context, scope, after string, since time.Time, limit int) ([]ProxyActivity, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(`SELECT owner_uid, namespace, last_seen_ms FROM proxy_activity
		WHERE scope = ? AND owner_uid > ? AND last_seen_ms >= ? ORDER BY owner_uid LIMIT ?`), scope, after, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ProxyActivity
	for rows.Next() {
		var r ProxyActivity
		var ms int64
		if err := rows.Scan(&r.OwnerUID, &r.Namespace, &ms); err != nil {
			return nil, err
		}
		r.LastSeen = time.UnixMilli(ms).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneProxyActivity drops rows last seen before cutoff.
func (s *SQLStore) PruneProxyActivity(ctx context.Context, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM proxy_activity WHERE last_seen_ms < ?`), cutoff.UnixMilli())
	return err
}

// proxyActivityRoom refuses rows that would take scope past maxRows. It counts
// the rows already held only when the report could cross the ceiling.
func (s *SQLStore) proxyActivityRoom(ctx context.Context, scope string, rows []ProxyActivity, maxRows int) error {
	var held int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM proxy_activity WHERE scope = ?`), scope).Scan(&held); err != nil {
		return err
	}
	if held+len(rows) <= maxRows {
		return nil
	}
	known := 0
	for start := 0; start < len(rows); start += proxyActivityChunk {
		chunk := rows[start:min(start+proxyActivityChunk, len(rows))]
		marks := make([]string, len(chunk))
		args := []any{scope}
		for i, r := range chunk {
			marks[i] = "?"
			args = append(args, r.OwnerUID)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM proxy_activity WHERE scope = ? AND owner_uid IN (`+
			strings.Join(marks, ", ")+`)`), args...).Scan(&n); err != nil { // #nosec G202 -- placeholders only
			return err
		}
		known += n
	}
	if held+len(rows)-known > maxRows {
		return ErrProxyActivityFull
	}
	return nil
}

// ProxyActivityHistory returns when scope's history began, and false if it
// has none.
func (s *SQLStore) ProxyActivityHistory(ctx context.Context, scope string) (time.Time, bool, error) {
	var ms int64
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT history_started_ms FROM proxy_activity_scope WHERE scope = ?`), scope).Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(ms).UTC(), true, nil
}

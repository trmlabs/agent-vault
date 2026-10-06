package store

import (
	"context"
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

// RecordProxyActivity keeps, per Sandbox, the latest of the stored and the
// reported times. A row repeated within rows keeps its latest time.
func (s *SQLStore) RecordProxyActivity(ctx context.Context, scope string, rows []ProxyActivity) error {
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

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BindRunnerSession pins a runner session token hash to the first Pod that
// presents it and returns the Pod it is pinned to. A pin lasts until the
// token's own expiry; expired pins are removed as new ones are written. The
// same table pins a Cursor worker Pod ("cursor-pod:<uid>") to its first run
// owner, so any key and value pair works.
func (s *SQLStore) BindRunnerSession(ctx context.Context, tokenSHA256, pod string, expires time.Time) (string, error) {
	if tokenSHA256 == "" || pod == "" {
		return "", fmt.Errorf("incomplete runner session binding")
	}
	now := s.dbNowMs()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM runner_session_binding WHERE expires_ms <= `+now); err != nil { // #nosec G202 -- constant clock expression
		return "", err
	}
	// Two replicas may race on a first use; the primary key keeps one pin, and
	// both then read the same answer.
	_, insertErr := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO runner_session_binding (token, pod, expires_ms)
		SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM runner_session_binding WHERE token = ?)`), tokenSHA256, pod, expires.UnixMilli(), tokenSHA256)
	var bound string
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT pod FROM runner_session_binding WHERE token = ?`), tokenSHA256).Scan(&bound)
	if errors.Is(err, sql.ErrNoRows) && insertErr != nil {
		return "", insertErr
	}
	return bound, err
}

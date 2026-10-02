package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DatabaseCleanup stores only a revocation reference, never a token or password.
// ActorID names the actor whose connection minted the credential; an empty
// ActorID is unattributed (legacy or unknown) and counts against every actor.
// WorkloadID is that connection's verified runtime instance UID; an empty
// WorkloadID counts against every instance of the actor.
type DatabaseCleanup struct{ Accessor, Binding, LeaseID, ActorID, WorkloadID string }

// ErrReplicaNameInUse means another broker process that is still renewing its
// owner row uses the same replica name. Two processes under one name would
// share an audit chain and confuse cleanup ownership, so the later one must not
// run.
var ErrReplicaNameInUse = errors.New("another live broker process holds this replica name")

// replicaPattern is the LIKE pattern for every owner row of owner's replica,
// or "" when the owner carries no replica name. Replica names are DNS-style,
// so they hold no LIKE wildcards.
func replicaPattern(owner string) string {
	replica, _, ok := strings.Cut(owner, "/")
	if !ok || replica == "" {
		return ""
	}
	return replica + "/%"
}

// replicaNameInUse reports whether another live owner row shares owner's replica name.
func (s *SQLStore) replicaNameInUse(ctx context.Context, owner string) (bool, error) {
	pattern := replicaPattern(owner)
	if pattern == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM database_cleanup_replica
		WHERE owner LIKE ? AND owner <> ? AND expires_ms > `+s.dbNowMs()), pattern, owner).Scan(&n)
	return n > 0, err
}

// noOtherLiveReplicaOwner is a condition (binding pattern, owner) true while
// no other live owner row shares the replica name.
func (s *SQLStore) noOtherLiveReplicaOwner() string {
	return `NOT EXISTS (SELECT 1 FROM database_cleanup_replica other WHERE other.owner LIKE ? AND other.owner <> ? AND other.expires_ms > ` + s.dbNowMs() + `)`
}

// ErrDatabaseCleanupOwnershipLost means the owner row expired or was released.
// An expired owner can never renew, so its records belong to the survivors.
var ErrDatabaseCleanupOwnershipLost = errors.New("database cleanup ownership lost")

// ErrPodSessionLimit refuses a session beyond a Pod's fleet-wide cap.
var ErrPodSessionLimit = errors.New("pod session limit reached")

func (s *SQLStore) databaseCleanupExec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	// Share the committed, synchronous write boundary with the audit journal.
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

// dbNowMs is the database clock in Unix milliseconds. Every owner expiry is
// written and compared with it, so replica clocks never decide ownership.
func (s *SQLStore) dbNowMs() string {
	if s.dialect.Name() == "postgres" {
		return `CAST(EXTRACT(EPOCH FROM now()) * 1000 AS BIGINT)`
	}
	return `CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)`
}

// liveOwner is a condition true while the owner bound at that placeholder holds
// an unexpired row.
func (s *SQLStore) liveOwner() string {
	return `EXISTS (SELECT 1 FROM database_cleanup_replica WHERE owner = ? AND expires_ms > ` + s.dbNowMs() + `)`
}

func affectedOne(result sql.Result, err error, lost error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return lost
	}
	return nil
}

// ClaimDatabaseCleanupOwner registers one broker process. Owner IDs are unique
// per process, so any number of replicas may hold rows at once; each owns only
// the records it wrote or claimed.
func (s *SQLStore) ClaimDatabaseCleanupOwner(ctx context.Context, owner string, ttl time.Duration) error {
	if owner == "" || ttl <= 0 {
		return fmt.Errorf("invalid database cleanup owner")
	}
	// Owner IDs are replica/boot. A second live boot under one replica name is
	// refused here, in the same statement that registers the owner.
	pattern := replicaPattern(owner)
	var result sql.Result
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		// Under READ COMMITTED two boots starting together could both pass
		// the NOT EXISTS check; a transaction-scoped lock on the replica name
		// makes the check and the insert one step. SQLite writes are already
		// serialized.
		if pattern != "" && s.dialect.Name() == "postgres" {
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "gatehouse-replica:"+pattern); err != nil {
				return err
			}
		}
		var err error
		result, err = tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup_replica (owner, expires_ms)
		SELECT ?, `+s.dbNowMs()+` + ? WHERE NOT EXISTS (SELECT 1 FROM database_cleanup_replica WHERE owner = ?)
		AND (CAST(? AS TEXT) = '' OR `+s.noOtherLiveReplicaOwner()+`)`), owner, ttl.Milliseconds(), owner, pattern, pattern, owner)
		return err
	})
	if err = affectedOne(result, err, fmt.Errorf("database cleanup owner already registered")); err != nil {
		if inUse, checkErr := s.replicaNameInUse(ctx, owner); checkErr == nil && inUse {
			return ErrReplicaNameInUse
		}
	}
	return err
}

// RenewDatabaseCleanupOwner extends a live owner. It never revives an expired
// one: after expiry a survivor may already have claimed the records.
func (s *SQLStore) RenewDatabaseCleanupOwner(ctx context.Context, owner string, ttl time.Duration) error {
	now := s.dbNowMs()
	pattern := replicaPattern(owner)
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup_replica SET expires_ms = `+now+` + ?
		WHERE owner = ? AND expires_ms > `+now+` AND (CAST(? AS TEXT) = '' OR `+s.noOtherLiveReplicaOwner()+`)`), ttl.Milliseconds(), owner, pattern, pattern, owner)
	if err = affectedOne(result, err, ErrDatabaseCleanupOwnershipLost); errors.Is(err, ErrDatabaseCleanupOwnershipLost) {
		// Both processes under a duplicated name stop renewing and fence.
		if inUse, checkErr := s.replicaNameInUse(ctx, owner); checkErr == nil && inUse {
			return ErrReplicaNameInUse
		}
	}
	return err
}

// ReleaseDatabaseCleanupOwner ends ownership at once. Records the owner still
// holds become claimable by the next heartbeat of any survivor.
func (s *SQLStore) ReleaseDatabaseCleanupOwner(ctx context.Context, owner string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup_replica WHERE owner = ?`), owner)
	return err
}

// CheckDatabaseCleanupOwner verifies current fencing without extending it.
func (s *SQLStore) CheckDatabaseCleanupOwner(ctx context.Context, owner string) error {
	var owned bool
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+s.liveOwner()), owner).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return ErrDatabaseCleanupOwnershipLost
	}
	return nil
}

// LiveDatabaseCleanupOwners counts unexpired owners, the fleet's live replicas.
func (s *SQLStore) LiveDatabaseCleanupOwners(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM database_cleanup_replica WHERE expires_ms > `+s.dbNowMs()).Scan(&n)
	return n, err
}

// ClaimOrphanedDatabaseCleanup gives a live owner every unresolved record whose
// owner is expired, released or absent. Each record moves only from the owner
// read in the same statement, so when two survivors race, the second finds the
// record already owned by a live replica and claims nothing. It also drops
// session rows of dead owners and owner rows expired for a minute.
func (s *SQLStore) ClaimOrphanedDatabaseCleanup(ctx context.Context, owner string) (int, error) {
	now := s.dbNowMs()
	var claimed int64
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET owner = ?
			WHERE (accessor, owner) IN (SELECT accessor, owner FROM database_cleanup
				WHERE reconciliation_evidence = '' AND owner NOT IN (SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+now+`))
			AND `+s.liveOwner()), owner, owner)
		if err != nil {
			return err
		}
		if claimed, err = result.RowsAffected(); err != nil {
			return err
		}
		// #nosec G202 -- now is a constant SQL clock expression, not input.
		if _, err = tx.ExecContext(ctx, `DELETE FROM broker_sessions WHERE owner NOT IN
			(SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+now+`)`); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM database_cleanup_replica WHERE expires_ms <= `+now+` - 60000`) // #nosec G202 -- constant clock expression
		return err
	})
	return int(claimed), err
}

func (s *SQLStore) AddDatabaseCleanup(ctx context.Context, owner string, record DatabaseCleanup) error {
	if record.Accessor == "" || record.Binding == "" {
		return fmt.Errorf("incomplete database cleanup record")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup (accessor, binding, actor_id, workload_id, owner)
		SELECT ?, ?, ?, ?, ? WHERE `+s.liveOwner()), record.Accessor, record.Binding, record.ActorID, record.WorkloadID, owner, owner)
	return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
}

// ListDatabaseCleanup returns the whole fleet's unresolved records.
func (s *SQLStore) ListDatabaseCleanup(ctx context.Context) ([]DatabaseCleanup, error) {
	return s.listDatabaseCleanup(ctx, `SELECT accessor, binding, lease_id, actor_id, workload_id FROM database_cleanup WHERE reconciliation_evidence = '' ORDER BY accessor`)
}

// ListOwnedDatabaseCleanup returns only the records one owner must resolve.
func (s *SQLStore) ListOwnedDatabaseCleanup(ctx context.Context, owner string) ([]DatabaseCleanup, error) {
	return s.listDatabaseCleanup(ctx, s.dialect.Rebind(`SELECT accessor, binding, lease_id, actor_id, workload_id FROM database_cleanup
		WHERE reconciliation_evidence = '' AND owner = ? ORDER BY accessor`), owner)
}

func (s *SQLStore) listDatabaseCleanup(ctx context.Context, query string, args ...any) ([]DatabaseCleanup, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var records []DatabaseCleanup
	for rows.Next() {
		var record DatabaseCleanup
		if err := rows.Scan(&record.Accessor, &record.Binding, &record.LeaseID, &record.ActorID, &record.WorkloadID); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLStore) SetDatabaseCleanupLease(ctx context.Context, owner, accessor, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("database lease ID is required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET lease_id = ?
		WHERE accessor = ? AND owner = ? AND reconciliation_evidence = '' AND `+s.liveOwner()), leaseID, accessor, owner, owner)
	return affectedOne(result, err, fmt.Errorf("database cleanup ownership or record lost"))
}

// QuarantineDatabaseCleanup marks an issuance whose lease ID never arrived.
// The mark is fleet-wide: no replica reopens the binding until an operator
// confirms cleanup.
func (s *SQLStore) QuarantineDatabaseCleanup(ctx context.Context, owner, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET quarantined = 1
		WHERE accessor = ? AND owner = ? AND lease_id = '' AND reconciliation_evidence = ''`), accessor, owner)
	return err
}

// DatabaseBindingQuarantined reports a quarantined record on the binding held
// by any owner.
func (s *SQLStore) DatabaseBindingQuarantined(ctx context.Context, binding string) (bool, error) {
	var quarantined bool
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT EXISTS (SELECT 1 FROM database_cleanup
		WHERE binding = ? AND quarantined = 1 AND lease_id = '' AND reconciliation_evidence = '')`), binding).Scan(&quarantined)
	return quarantined, err
}

// ConfirmDatabaseCleanup is an explicit operator attestation, not an automated
// test result. Keep its evidence after removing the binding's quarantine. Any
// live replica may record it, whichever replica owns the record.
func (s *SQLStore) ConfirmDatabaseCleanup(ctx context.Context, owner, accessor, evidence string) error {
	if strings.TrimSpace(accessor) == "" || strings.TrimSpace(evidence) == "" {
		return fmt.Errorf("accessor and database reconciliation evidence are required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET reconciliation_evidence = ?
		WHERE accessor = ? AND lease_id = '' AND reconciliation_evidence = '' AND `+s.liveOwner()), evidence, accessor, owner)
	return affectedOne(result, err, fmt.Errorf("unknown-issuance record not found"))
}

func (s *SQLStore) DeleteDatabaseCleanup(ctx context.Context, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup WHERE accessor = ?`), accessor)
	return err
}

// AddBrokerSession records one client session against its Pod for a
// fleet-wide cap. A limit of zero records without a cap. Rows count only while
// their owner is live, so a dead replica's sessions drop out with it.
func (s *SQLStore) AddBrokerSession(ctx context.Context, owner, id, pod string, limit int) error {
	if owner == "" || id == "" || pod == "" {
		return fmt.Errorf("incomplete broker session")
	}
	return s.auditWrite(ctx, func(tx *sql.Tx) error {
		if s.dialect.Name() == "postgres" {
			// Serialize admissions per Pod across replicas; SQLite already has one writer.
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7956324892))`, pod); err != nil {
				return err
			}
		}
		if limit > 0 {
			n, err := s.countPodSessions(ctx, tx, pod)
			if err != nil {
				return err
			}
			if n >= limit {
				return ErrPodSessionLimit
			}
		}
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO broker_sessions (id, owner, pod)
			SELECT ?, ?, ? WHERE `+s.liveOwner()), id, owner, pod, owner)
		return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
	})
}

func (s *SQLStore) RemoveBrokerSession(ctx context.Context, id string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM broker_sessions WHERE id = ?`), id)
	return err
}

// CountPodSessions counts a Pod's sessions on live replicas.
func (s *SQLStore) CountPodSessions(ctx context.Context, pod string) (int, error) {
	return s.countPodSessions(ctx, s.db, pod)
}

func (s *SQLStore) countPodSessions(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, pod string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM broker_sessions WHERE pod = ? AND owner IN
		(SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+s.dbNowMs()+`)`), pod).Scan(&n)
	return n, err
}

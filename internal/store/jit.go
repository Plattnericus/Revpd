package store

import (
	"context"
	"fmt"
	"time"
)

// CreateJITRequest records a direct connection attempt awaiting approval.
//
// user_hint is whatever the client claimed. It is stored so the audit trail
// shows what was asserted, never as proof of who connected.
func (db *DB) CreateJITRequest(ctx context.Context, hint string, userID, targetID int64, srcIP string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO jit_requests (user_hint, matched_user_id, target_id, src_ip, state, created_at)
		 VALUES (?, ?, ?, ?, 'pending', ?)`,
		hint, userID, targetID, srcIP, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("create jit request: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) SetJITState(ctx context.Context, id int64, state, via string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE jit_requests SET state = ?, decided_at = ?, decided_via = ?
		 WHERE id = ? AND state = 'pending'`,
		state, time.Now().Unix(), via, id)
	if err != nil {
		return fmt.Errorf("set jit state: %w", err)
	}
	return nil
}

// PendingJITCount backs the per-IP cap, so one address cannot flood a phone
// with approval prompts.
func (db *DB) PendingJITCount(ctx context.Context, srcIP string, since time.Time) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM jit_requests
		 WHERE src_ip = ? AND state = 'pending' AND created_at >= ?`,
		srcIP, since.Unix()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending jit requests: %w", err)
	}
	return n, nil
}

// ExpirePendingJIT sweeps requests nobody ever answered.
func (db *DB) ExpirePendingJIT(ctx context.Context, olderThan time.Time) error {
	_, err := db.ExecContext(ctx,
		`UPDATE jit_requests SET state = 'timeout', decided_at = unixepoch(), decided_via = 'expired'
		 WHERE state = 'pending' AND created_at < ?`, olderThan.Unix())
	if err != nil {
		return fmt.Errorf("expire pending jit requests: %w", err)
	}
	return nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RedirectToken ties a redirected reconnect back to the login that caused it.
type RedirectToken struct {
	ID       int64
	UserID   int64
	TargetID int64
	SrcIP    string
}

// CreateRedirectToken records a token the client is about to be handed.
//
// Only the hash is stored: the token itself travels in the redirection packet
// and comes back in the routing token, and neither should be recoverable from
// the database if it ever leaks.
func (db *DB) CreateRedirectToken(ctx context.Context, tokenHash string, userID, targetID int64, srcIP string, ttl time.Duration) error {
	now := time.Now()

	_, err := db.ExecContext(ctx,
		`INSERT INTO redirect_tokens (token_hash, user_id, target_id, src_ip, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash, userID, targetID, srcIP, now.Unix(), now.Add(ttl).Unix())
	if err != nil {
		return fmt.Errorf("create redirect token: %w", err)
	}
	return nil
}

// ConsumeRedirectToken claims a token exactly once.
//
// The UPDATE both checks and claims in one statement, so two connections
// racing with the same token cannot both win.
func (db *DB) ConsumeRedirectToken(ctx context.Context, tokenHash, srcIP string) (*RedirectToken, error) {
	now := time.Now().Unix()

	res, err := db.ExecContext(ctx,
		`UPDATE redirect_tokens SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND src_ip = ?`,
		now, tokenHash, now, srcIP)
	if err != nil {
		return nil, fmt.Errorf("claim redirect token: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrNotFound
	}

	var t RedirectToken
	err = db.QueryRowContext(ctx,
		`SELECT id, user_id, target_id, src_ip FROM redirect_tokens WHERE token_hash = ?`,
		tokenHash).Scan(&t.ID, &t.UserID, &t.TargetID, &t.SrcIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read redirect token: %w", err)
	}
	return &t, nil
}

// PurgeRedirectTokens drops spent and stale rows.
func (db *DB) PurgeRedirectTokens(ctx context.Context, olderThan time.Time) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM redirect_tokens WHERE expires_at < ?`, olderThan.Unix())
	if err != nil {
		return fmt.Errorf("purge redirect tokens: %w", err)
	}
	return nil
}

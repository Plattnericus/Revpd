package store

import (
	"context"
	"errors"
	"fmt"
)

// BackupCode is one unused recovery code.
type BackupCode struct {
	ID   int64
	Hash string
}

// OpenBackupCodes returns the codes this account has left.
//
// It reads everything and closes the cursor before returning on purpose: the
// connection pool holds a single connection, so a caller that writes while a
// query is still streaming would deadlock against itself.
func (db *DB) OpenBackupCodes(ctx context.Context, userID int64) ([]BackupCode, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used_at IS NULL`, userID)
	if err != nil {
		return nil, fmt.Errorf("list backup codes: %w", err)
	}
	defer rows.Close()

	out := []BackupCode{}
	for rows.Next() {
		var c BackupCode
		if err := rows.Scan(&c.ID, &c.Hash); err != nil {
			return nil, fmt.Errorf("scan backup code: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ErrCodeAlreadyUsed means someone else spent it first.
var ErrCodeAlreadyUsed = errors.New("backup code already used")

// ClaimBackupCode marks a code spent, once.
func (db *DB) ClaimBackupCode(ctx context.Context, id int64) error {
	res, err := db.ExecContext(ctx,
		`UPDATE backup_codes SET used_at = unixepoch() WHERE id = ? AND used_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("claim backup code: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCodeAlreadyUsed
	}
	return nil
}

// CountBackupCodes reports how many are left, for the UI.
func (db *DB) CountBackupCodes(ctx context.Context, userID int64) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM backup_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count backup codes: %w", err)
	}
	return n, nil
}

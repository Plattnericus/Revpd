package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// Setting reads an operator preference. The second return says whether one was
// ever set, so callers can fall back to the value from revpd.yaml rather than
// to a zero value that means something quite different.
func (db *DB) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting records a preference and who changed it.
func (db *DB) SetSetting(ctx context.Context, key, value, by string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO app_settings (key, value, updated_at, updated_by)
		VALUES (?, ?, unixepoch(), ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
		key, value, by)
	return err
}

// BoolSetting is Setting for the on/off preferences, with the configured
// default applied when nobody has expressed a choice yet.
func (db *DB) BoolSetting(ctx context.Context, key string, def bool) bool {
	v, ok, err := db.Setting(ctx, key)
	if err != nil || !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// SetBoolSetting stores an on/off preference.
func (db *DB) SetBoolSetting(ctx context.Context, key string, v bool, by string) error {
	return db.SetSetting(ctx, key, strconv.FormatBool(v), by)
}

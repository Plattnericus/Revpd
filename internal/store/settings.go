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

// AllSettings returns every stored override, for layering over the file.
func (db *DB) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SettingMeta is who last changed a value and when.
type SettingMeta struct {
	Value     string
	UpdatedAt int64
	UpdatedBy string
}

// SettingsWithMeta is AllSettings plus the audit columns, for a page that
// shows which values somebody has taken control of.
func (db *DB) SettingsWithMeta(ctx context.Context) (map[string]SettingMeta, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT key, value, updated_at, updated_by FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]SettingMeta{}
	for rows.Next() {
		var k string
		var m SettingMeta
		if err := rows.Scan(&k, &m.Value, &m.UpdatedAt, &m.UpdatedBy); err != nil {
			return nil, err
		}
		out[k] = m
	}
	return out, rows.Err()
}

// ClearSetting drops an override, handing the setting back to revpd.yaml.
func (db *DB) ClearSetting(ctx context.Context, key string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM app_settings WHERE key = ?`, key)
	return err
}

// ReplaceSettings stores a whole set of overrides in one transaction, so a
// save that fails part-way cannot leave half of it applied.
func (db *DB) ReplaceSettings(ctx context.Context, values map[string]string, by string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_settings (key, value, updated_at, updated_by)
			VALUES (?, ?, unixepoch(), ?)
			ON CONFLICT(key) DO UPDATE SET
				value = excluded.value,
				updated_at = excluded.updated_at,
				updated_by = excluded.updated_by`, k, v, by); err != nil {
			return err
		}
	}
	return tx.Commit()
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

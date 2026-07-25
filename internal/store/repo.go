package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")

/* ----------------------------------------------------------------- users --- */

type User struct {
	ID              int64
	Username        string
	DisplayName     string
	PasswordHash    string
	Role            string
	RDPHint         string
	TOTPSecretEnc   []byte
	TOTPLastCounter int64
	Status          string
	CreatedAt       time.Time
}

func (u User) IsAdmin() bool  { return u.Role == "admin" }
func (u User) IsActive() bool { return u.Status == "active" }

const userCols = `id, username, display_name, password_hash, role, rdp_hint,
                  totp_secret_enc, totp_last_counter, status, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created int64
	var secret []byte

	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role,
		&u.RDPHint, &secret, &u.TOTPLastCounter, &u.Status, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	u.TOTPSecretEnc = secret
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

func (db *DB) CreateUser(ctx context.Context, u User) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (username, display_name, password_hash, role, rdp_hint, status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'active', ?)`,
		u.Username, u.DisplayName, u.PasswordHash, u.Role, u.RDPHint, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("create user %s: %w", u.Username, err)
	}
	return res.LastInsertId()
}

func (db *DB) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

func (db *DB) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByRDPHint resolves the mstshash cookie to an account.
//
// The hint is attacker-controlled, so this only ever selects who gets asked for
// approval. It grants nothing on its own.
func (db *DB) UserByRDPHint(ctx context.Context, hint string) (*User, error) {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return nil, ErrNotFound
	}

	// mstsc often sends DOMAIN\user; we match on the bare name.
	if i := strings.LastIndex(hint, "\\"); i >= 0 {
		hint = hint[i+1:]
	}
	if i := strings.Index(hint, "@"); i > 0 {
		hint = hint[:i]
	}

	return scanUser(db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users
		 WHERE status = 'active' AND (lower(username) = lower(?) OR (rdp_hint <> '' AND lower(rdp_hint) = lower(?)))
		 LIMIT 1`, hint, hint))
}

// ErrCounterAlreadyUsed means another login got to this step first.
var ErrCounterAlreadyUsed = errors.New("this one-time code has already been used")

// ClaimTOTPCounter burns a TOTP step, and reports whether this caller is the
// one that burned it.
//
// The check and the write are a single statement on purpose. Reading the
// counter and then updating it would leave a window in which several logins
// all see the same old value and all decide their code is fresh — which is
// exactly the replay the counter exists to stop. The WHERE clause makes SQLite
// arbitrate, and RowsAffected says who won.
func (db *DB) ClaimTOTPCounter(ctx context.Context, userID, counter int64) error {
	res, err := db.ExecContext(ctx,
		`UPDATE users SET totp_last_counter = ? WHERE id = ? AND totp_last_counter < ?`,
		counter, userID, counter)
	if err != nil {
		return fmt.Errorf("claim totp counter: %w", err)
	}

	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCounterAlreadyUsed
	}
	return nil
}

// SetTOTPCounter is the older spelling, kept for callers that only want the
// counter moved forward and do not care who did it.
//
// Deprecated: use ClaimTOTPCounter anywhere a login depends on the result.
func (db *DB) SetTOTPCounter(ctx context.Context, userID, counter int64) error {
	err := db.ClaimTOTPCounter(ctx, userID, counter)
	if errors.Is(err, ErrCounterAlreadyUsed) {
		return nil
	}
	return err
}

func (db *DB) SetTOTPSecret(ctx context.Context, userID int64, enc []byte) error {
	_, err := db.ExecContext(ctx,
		`UPDATE users SET totp_secret_enc = ?, totp_last_counter = 0 WHERE id = ?`, enc, userID)
	if err != nil {
		return fmt.Errorf("store totp secret: %w", err)
	}
	return nil
}

// DeleteUser removes an account and everything attached to it.
//
// The foreign keys carry the rest: backup codes, passkeys, target grants,
// sessions and grants are ON DELETE CASCADE, and the audit trail keeps its
// entries because it references nothing.
func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTarget removes a machine. Past sessions survive with a null target, so
// the activity log does not lose its history.
func (db *DB) DeleteTarget(ctx context.Context, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete target: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TargetByName resolves the name people actually type on the command line.
func (db *DB) TargetByName(ctx context.Context, name string) (*Target, error) {
	return scanTarget(db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE name = ?`, name))
}

func (db *DB) SetUserStatus(ctx context.Context, userID int64, status string) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ?`, status, userID)
	if err != nil {
		return fmt.Errorf("set user status: %w", err)
	}
	return nil
}

func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

/* --------------------------------------------------------------- targets --- */

type Target struct {
	ID           int64
	Name         string
	Hostname     string
	IP           string
	RDPPort      int
	MAC          string
	WoLBroadcast string
	WoLPort      int
	BootTimeoutS int
	Icon         string
	Notes        string
}

// Addr is where the relay dials. Hostname wins so DHCP churn does not break it.
func (t Target) Addr() string {
	host := t.Hostname
	if host == "" {
		host = t.IP
	}
	return net.JoinHostPort(host, fmt.Sprint(t.RDPPort))
}

const targetCols = `id, name, hostname, ip, rdp_port, mac, wol_broadcast, wol_port,
                    boot_timeout_s, icon, notes`

func scanTarget(row interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	err := row.Scan(&t.ID, &t.Name, &t.Hostname, &t.IP, &t.RDPPort, &t.MAC,
		&t.WoLBroadcast, &t.WoLPort, &t.BootTimeoutS, &t.Icon, &t.Notes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan target: %w", err)
	}
	return &t, nil
}

func (db *DB) CreateTarget(ctx context.Context, t Target) (int64, error) {
	if t.RDPPort == 0 {
		t.RDPPort = 3389
	}
	if t.WoLPort == 0 {
		t.WoLPort = 9
	}
	if t.WoLBroadcast == "" {
		t.WoLBroadcast = "255.255.255.255"
	}
	if t.BootTimeoutS == 0 {
		t.BootTimeoutS = 120
	}
	if t.Icon == "" {
		t.Icon = "monitor"
	}

	res, err := db.ExecContext(ctx,
		`INSERT INTO targets (name, hostname, ip, rdp_port, mac, wol_broadcast, wol_port,
		                      boot_timeout_s, icon, notes, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Name, t.Hostname, t.IP, t.RDPPort, t.MAC, t.WoLBroadcast, t.WoLPort,
		t.BootTimeoutS, t.Icon, t.Notes, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("create target %s: %w", t.Name, err)
	}
	return res.LastInsertId()
}

func (db *DB) TargetByID(ctx context.Context, id int64) (*Target, error) {
	return scanTarget(db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ?`, id))
}

func (db *DB) ListTargets(ctx context.Context) ([]Target, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+targetCols+` FROM targets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// ListTargetsForUser returns only what this account may reach. Admins see all.
func (db *DB) ListTargetsForUser(ctx context.Context, u *User) ([]Target, error) {
	if u.IsAdmin() {
		return db.ListTargets(ctx)
	}

	rows, err := db.QueryContext(ctx,
		`SELECT `+prefixed(targetCols, "t")+`
		 FROM targets t
		 JOIN user_targets ut ON ut.target_id = t.id
		 WHERE ut.user_id = ?
		 ORDER BY t.name`, u.ID)
	if err != nil {
		return nil, fmt.Errorf("list targets for user: %w", err)
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// CanReach is the authorisation check. Everything that issues a grant calls it.
func (db *DB) CanReach(ctx context.Context, u *User, targetID int64) (bool, error) {
	if !u.IsActive() {
		return false, nil
	}
	if u.IsAdmin() {
		return true, nil
	}

	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM user_targets WHERE user_id = ? AND target_id = ?`,
		u.ID, targetID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check target access: %w", err)
	}
	return n > 0, nil
}

func (db *DB) GrantTargetAccess(ctx context.Context, userID, targetID int64) error {
	_, err := db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_targets (user_id, target_id) VALUES (?, ?)`, userID, targetID)
	if err != nil {
		return fmt.Errorf("grant target access: %w", err)
	}
	return nil
}

func (db *DB) RevokeTargetAccess(ctx context.Context, userID, targetID int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM user_targets WHERE user_id = ? AND target_id = ?`, userID, targetID)
	if err != nil {
		return fmt.Errorf("revoke target access: %w", err)
	}
	return nil
}

func prefixed(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
)

type Grant struct {
	ID         int64
	UserID     int64
	TargetID   int64
	SrcIP      string
	Mode       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// NormalizeIP reduces an address to the form grants are keyed on.
//
// Mobile clients hop within a carrier block between the browser request and the
// RDP connect, so operators can widen the match. Narrower is safer; the default
// is an exact v4 match and a /64 for v6, which is still a single subscriber.
func NormalizeIP(ip net.IP, v4Bits, v6Bits int) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if v4Bits >= 32 {
			return v4.String()
		}
		return v4.Mask(net.CIDRMask(v4Bits, 32)).String() + "/" + fmt.Sprint(v4Bits)
	}
	if v6Bits >= 128 {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(v6Bits, 128)).String() + "/" + fmt.Sprint(v6Bits)
}

func (db *DB) CreateGrant(ctx context.Context, g Grant, tokenHash string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO grants (user_id, target_id, src_ip, token_hash, mode, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.UserID, g.TargetID, g.SrcIP, tokenHash, g.Mode,
		g.CreatedAt.Unix(), g.ExpiresAt.Unix())
	if err != nil {
		return 0, fmt.Errorf("create grant: %w", err)
	}
	return res.LastInsertId()
}

// ActiveGrant finds a live grant for this address.
//
// This is the single query standing between the open internet and the target,
// so every condition here matters: not revoked, not expired, and bound to the
// address the packets are actually coming from.
func (db *DB) ActiveGrant(ctx context.Context, srcIP string, now time.Time) (*Grant, error) {
	var (
		g        Grant
		created  int64
		expires  int64
		consumed sql.NullInt64
	)

	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, target_id, src_ip, mode, created_at, expires_at, consumed_at
		 FROM grants
		 WHERE src_ip = ?
		   AND revoked_at IS NULL
		   AND expires_at > ?
		 ORDER BY id DESC
		 LIMIT 1`, srcIP, now.Unix()).
		Scan(&g.ID, &g.UserID, &g.TargetID, &g.SrcIP, &g.Mode, &created, &expires, &consumed)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("look up grant: %w", err)
	}

	g.CreatedAt = time.Unix(created, 0)
	g.ExpiresAt = time.Unix(expires, 0)
	if consumed.Valid {
		t := time.Unix(consumed.Int64, 0)
		g.ConsumedAt = &t
	}
	return &g, nil
}

// ConsumeGrant marks the first use and extends the window so mstsc can
// reconnect after a network blip without a fresh MFA round.
func (db *DB) ConsumeGrant(ctx context.Context, id int64, reuseUntil time.Time) error {
	_, err := db.ExecContext(ctx,
		`UPDATE grants
		 SET consumed_at = coalesce(consumed_at, unixepoch()),
		     expires_at  = max(expires_at, ?)
		 WHERE id = ? AND revoked_at IS NULL`,
		reuseUntil.Unix(), id)
	if err != nil {
		return fmt.Errorf("consume grant: %w", err)
	}
	return nil
}

// RevokeGrantsForUser is what "lock this account" has to do to be meaningful.
func (db *DB) RevokeGrantsForUser(ctx context.Context, userID int64) error {
	_, err := db.ExecContext(ctx,
		`UPDATE grants SET revoked_at = unixepoch() WHERE user_id = ? AND revoked_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("revoke user grants: %w", err)
	}
	return nil
}

// PurgeExpired keeps the table from growing without bound.
func (db *DB) PurgeExpired(ctx context.Context, olderThan time.Time) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM grants WHERE expires_at < ?`, olderThan.Unix()); err != nil {
		return fmt.Errorf("purge grants: %w", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, olderThan.Unix()); err != nil {
		return fmt.Errorf("purge sessions: %w", err)
	}
	return nil
}

/* --------------------------------------------------------- rdp sessions --- */

func (db *DB) OpenRDPSession(ctx context.Context, grantID, targetID int64, srcIP string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO rdp_sessions (grant_id, target_id, src_ip, started_at) VALUES (?, ?, ?, ?)`,
		grantID, targetID, srcIP, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("open rdp session: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) CloseRDPSession(ctx context.Context, id, in, out int64, reason string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE rdp_sessions SET ended_at = ?, bytes_in = ?, bytes_out = ?, close_reason = ?
		 WHERE id = ? AND ended_at IS NULL`,
		time.Now().Unix(), in, out, reason, id)
	if err != nil {
		return fmt.Errorf("close rdp session: %w", err)
	}
	return nil
}

type LiveSession struct {
	ID        int64
	Username  string
	Target    string
	SrcIP     string
	StartedAt time.Time
}

func (db *DB) ListLiveSessions(ctx context.Context) ([]LiveSession, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT s.id, coalesce(u.username, '?'), coalesce(t.name, '?'), s.src_ip, s.started_at
		 FROM rdp_sessions s
		 LEFT JOIN grants  g ON g.id = s.grant_id
		 LEFT JOIN users   u ON u.id = g.user_id
		 LEFT JOIN targets t ON t.id = s.target_id
		 WHERE s.ended_at IS NULL
		 ORDER BY s.started_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list live sessions: %w", err)
	}
	defer rows.Close()

	out := []LiveSession{}
	for rows.Next() {
		var s LiveSession
		var started int64
		if err := rows.Scan(&s.ID, &s.Username, &s.Target, &s.SrcIP, &started); err != nil {
			return nil, fmt.Errorf("scan live session: %w", err)
		}
		s.StartedAt = time.Unix(started, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// MarkStaleSessionsClosed tidies up rows left behind by a crash.
func (db *DB) MarkStaleSessionsClosed(ctx context.Context) error {
	_, err := db.ExecContext(ctx,
		`UPDATE rdp_sessions SET ended_at = unixepoch(), close_reason = 'gateway restarted'
		 WHERE ended_at IS NULL`)
	if err != nil {
		return fmt.Errorf("close stale sessions: %w", err)
	}
	return nil
}

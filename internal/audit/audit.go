// Package audit provides a tamper-evident, append-only event log.
//
// Every row carries the hash of the row before it. Deleting or editing an entry
// after the fact breaks the chain, and `revpd audit verify` will say where.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// genesis is the prev_hash of the very first entry.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Action names. Keep these stable — the UI filters on them.
const (
	ActionLoginOK        = "login.ok"
	ActionLoginFail      = "login.fail"
	ActionMFAOK          = "mfa.ok"
	ActionMFAFail        = "mfa.fail"
	ActionLogout         = "logout"
	ActionLockout        = "lockout"
	ActionGrantIssued    = "grant.issued"
	ActionGrantConsumed  = "grant.consumed"
	ActionGrantRevoked   = "grant.revoked"
	ActionGrantDenied    = "grant.denied"
	ActionWolSent        = "wol.sent"
	ActionTargetOnline   = "target.online"
	ActionTargetTimeout  = "target.timeout"
	ActionRelayOpen      = "relay.open"
	ActionRelayClose     = "relay.close"
	ActionRelayRejected  = "relay.rejected"
	ActionJITRequested   = "jit.requested"
	ActionJITApproved    = "jit.approved"
	ActionJITDenied      = "jit.denied"
	ActionJITTimeout     = "jit.timeout"
	ActionUserCreated    = "user.created"
	ActionUserUpdated    = "user.updated"
	ActionUserDeleted    = "user.deleted"
	ActionTargetCreated  = "target.created"
	ActionTargetUpdated  = "target.updated"
	ActionTargetDeleted  = "target.deleted"
	ActionSettingsUpdate = "settings.updated"
	ActionEnrollTOTP     = "enroll.totp"
	ActionEnrollPasskey  = "enroll.passkey"
	ActionMFAReset       = "mfa.reset"
)

// Entry is one thing that happened. Detail must never hold secrets.
type Entry struct {
	ID     int64          `json:"id"`
	TS     time.Time      `json:"ts"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Object string         `json:"object"`
	SrcIP  string         `json:"src_ip"`
	Detail map[string]any `json:"detail"`
	Hash   string         `json:"hash"`
}

type Log struct {
	db *sql.DB

	// Appends must serialize: two writers racing would both read the same
	// prev_hash and fork the chain.
	mu   sync.Mutex
	last string
}

func New(db *sql.DB) (*Log, error) {
	l := &Log{db: db}

	var h string
	err := db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&h)
	switch {
	case err == sql.ErrNoRows:
		l.last = genesis
	case err != nil:
		return nil, fmt.Errorf("read audit head: %w", err)
	default:
		l.last = h
	}
	return l, nil
}

// Append writes an entry and links it to the previous one.
func (l *Log) Append(ctx context.Context, e Entry) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}

	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("marshal audit detail: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ts := e.TS.UnixMilli()
	h := chainHash(l.last, ts, e.Actor, e.Action, e.Object, e.SrcIP, string(detail))

	_, err = l.db.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, object, src_ip, detail_json, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, e.Actor, e.Action, e.Object, e.SrcIP, string(detail), l.last, h)
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}

	l.last = h
	return nil
}

// Head returns the current chain tip, handy for health checks.
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Break describes where verification failed.
type Break struct {
	ID     int64
	Reason string
}

// Verify walks the whole chain. A nil Break means the log is intact.
func (l *Log) Verify(ctx context.Context) (*Break, int, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, object, src_ip, detail_json, prev_hash, hash
		 FROM audit_log ORDER BY id`)
	if err != nil {
		return nil, 0, fmt.Errorf("scan audit log: %w", err)
	}
	defer rows.Close()

	prev := genesis
	n := 0

	for rows.Next() {
		var (
			id                                              int64
			ts                                              int64
			actor, action, object, srcIP, detail, ph, stored string
		)
		if err := rows.Scan(&id, &ts, &actor, &action, &object, &srcIP, &detail, &ph, &stored); err != nil {
			return nil, n, fmt.Errorf("scan audit row: %w", err)
		}
		n++

		if ph != prev {
			return &Break{id, "prev_hash does not match the entry before it — a row was removed or reordered"}, n, nil
		}
		if want := chainHash(prev, ts, actor, action, object, srcIP, detail); want != stored {
			return &Break{id, "content hash mismatch — this row was edited"}, n, nil
		}
		prev = stored
	}
	if err := rows.Err(); err != nil {
		return nil, n, fmt.Errorf("iterate audit log: %w", err)
	}
	return nil, n, nil
}

// chainHash binds each entry to its predecessor.
//
// Fields are length-prefixed so that moving a character across a boundary
// (say "ab"+"c" vs "a"+"bc") cannot produce the same digest.
func chainHash(prev string, ts int64, actor, action, object, srcIP, detail string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	for _, f := range []string{strconv.FormatInt(ts, 10), actor, action, object, srcIP, detail} {
		h.Write([]byte(strconv.Itoa(len(f))))
		h.Write([]byte{':'})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Query holds the filters the activity page exposes.
type Query struct {
	Actor  string
	Action string
	Since  time.Time
	Limit  int
}

// List returns entries newest-first.
func (l *Log) List(ctx context.Context, q Query) ([]Entry, error) {
	var (
		where []string
		args  []any
	)
	if q.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, q.Actor)
	}
	if q.Action != "" {
		where = append(where, "action = ?")
		args = append(args, q.Action)
	}
	if !q.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 200
	}

	sqlStr := `SELECT id, ts, actor, action, object, src_ip, detail_json, hash FROM audit_log`
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY id DESC LIMIT ?"
	args = append(args, q.Limit)

	rows, err := l.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	out := []Entry{}
	for rows.Next() {
		var (
			e      Entry
			ts     int64
			detail string
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Object, &e.SrcIP, &detail, &e.Hash); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		e.TS = time.UnixMilli(ts)
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			e.Detail = map[string]any{"_raw": detail}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

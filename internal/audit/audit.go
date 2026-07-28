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
	ActionUpdateChecked  = "update.checked"
	ActionUpdateStaged   = "update.staged"
	ActionUpdateApplied  = "update.applied"
	ActionEnrollTOTP     = "enroll.totp"
	ActionEnrollPasskey  = "enroll.passkey"
	ActionMFAReset       = "mfa.reset"
)

// Actions lists every action name in the order they are declared above, for
// anything that has to check whether a name someone typed is real.
func Actions() []string {
	return []string{
		ActionLoginOK, ActionLoginFail, ActionMFAOK, ActionMFAFail, ActionLogout, ActionLockout,
		ActionGrantIssued, ActionGrantConsumed, ActionGrantRevoked, ActionGrantDenied,
		ActionWolSent, ActionTargetOnline, ActionTargetTimeout,
		ActionRelayOpen, ActionRelayClose, ActionRelayRejected,
		ActionJITRequested, ActionJITApproved, ActionJITDenied, ActionJITTimeout,
		ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionTargetCreated, ActionTargetUpdated, ActionTargetDeleted,
		ActionSettingsUpdate, ActionUpdateChecked, ActionUpdateStaged, ActionUpdateApplied,
		ActionEnrollTOTP, ActionEnrollPasskey, ActionMFAReset,
	}
}

// KnownAction reports whether name is one of the actions above.
func KnownAction(name string) bool {
	for _, a := range Actions() {
		if a == name {
			return true
		}
	}
	return false
}

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
	// prev_hash and fork the chain. The mutex covers this process; the
	// transaction in append covers the command line running alongside the
	// service, which is a second process on the same file.
	mu sync.Mutex

	// Watchers are told about entries that made it into the chain. Registered
	// at startup and read on every append, which is what the second mutex is
	// for — the chain mutex must not be held while somebody else's code runs.
	watchMu  sync.RWMutex
	watchers []func(Entry)
}

func New(db *sql.DB) (*Log, error) {
	l := &Log{db: db}

	// Fail here rather than on the first event if the table is unusable.
	if _, err := l.head(context.Background()); err != nil {
		return nil, fmt.Errorf("read audit head: %w", err)
	}
	return l, nil
}

func (l *Log) head(ctx context.Context) (string, error) {
	var h string
	err := l.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&h)
	switch {
	case err == sql.ErrNoRows:
		return genesis, nil
	case err != nil:
		return "", err
	}
	return h, nil
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

	if err := l.appendChained(ctx, e, string(detail)); err != nil {
		return err
	}

	// Only entries that are actually in the chain are announced. A watcher that
	// heard about a failed write would report something that never happened.
	l.watchMu.RLock()
	defer l.watchMu.RUnlock()
	for _, fn := range l.watchers {
		fn(e)
	}
	return nil
}

// Watch registers a function to be called after every entry that is written.
//
// It runs on the goroutine that logged the event — which is often one holding a
// TCP connection open — so a watcher must return promptly and do its real work
// somewhere else.
func (l *Log) Watch(fn func(Entry)) {
	if fn == nil {
		return
	}
	l.watchMu.Lock()
	defer l.watchMu.Unlock()
	l.watchers = append(l.watchers, fn)
}

func (l *Log) appendChained(ctx context.Context, e Entry, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := e.TS.UnixMilli()

	// Remembering the head between calls looks tempting and is wrong: the
	// service and `revpd` on the command line are two processes on one file,
	// so either one writing leaves the other's copy pointing at a row that is
	// no longer last. The next entry would then chain to the wrong place and
	// verification would cry tampering over ordinary administration.
	//
	// So the head is read and extended inside a single transaction. When the
	// other writer wins the race SQLite refuses the commit, and we take a
	// fresh look rather than writing a fork.
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		if err = l.appendOnce(ctx, e, ts, detail); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 2 * time.Millisecond)
	}
	return fmt.Errorf("append audit entry: %w", err)
}

func (l *Log) appendOnce(ctx context.Context, e Entry, ts int64, detail string) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	prev := genesis
	var h string
	switch err := tx.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&h); {
	case err == sql.ErrNoRows:
	case err != nil:
		return err
	default:
		prev = h
	}

	hash := chainHash(prev, ts, e.Actor, e.Action, e.Object, e.SrcIP, detail)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, object, src_ip, detail_json, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, e.Actor, e.Action, e.Object, e.SrcIP, detail, prev, hash); err != nil {
		return err
	}
	return tx.Commit()
}

// Head returns the current chain tip, handy for health checks.
func (l *Log) Head() string {
	h, err := l.head(context.Background())
	if err != nil {
		return ""
	}
	return h
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
			id                                               int64
			ts                                               int64
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

// Package auth handles login state: sessions, CSRF and brute-force lockout.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/store"
)

// Cookie names.
//
// The __Host- prefix pins a cookie to this exact origin and path, so a
// subdomain cannot overwrite it. Browsers only honour it on a Secure cookie
// and silently drop it otherwise — which would leave the portal unusable over
// plain HTTP, including the first-run wizard that has to happen before any
// certificate exists.
//
// So the prefix is applied when the connection can carry it, and dropped when
// it cannot. Losing it on plain HTTP costs nothing that plain HTTP had.
const (
	sessionName = "revpd_session"
	csrfName    = "revpd_csrf"

	CSRFHeader = "X-CSRF-Token"
)

// SessionCookieName returns the name to use for this connection.
func SessionCookieName(secure bool) string { return cookieName(sessionName, secure) }

// CSRFCookieName returns the name to use for this connection.
func CSRFCookieName(secure bool) string { return cookieName(csrfName, secure) }

func cookieName(base string, secure bool) string {
	if secure {
		return "__Host-" + base
	}
	return base
}

// readCookie finds a cookie under either spelling, so a gateway that gains a
// certificate does not log everyone out at once.
func readCookie(r *http.Request, base string) string {
	for _, name := range []string{"__Host-" + base, base} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// SessionToken pulls the session cookie off a request.
func SessionToken(r *http.Request) string { return readCookie(r, sessionName) }

var (
	ErrNoSession   = errors.New("no valid session")
	ErrLockedOut   = errors.New("too many failed attempts")
	ErrBadPassword = errors.New("wrong username or password")
)

// Stage tracks how far a login has got. A session that has only passed the
// password step can do nothing but finish MFA.
type Stage string

const (
	StagePending Stage = "pending" // password accepted, second factor still owed
	StageFull    Stage = "full"    // fully authenticated
)

type Session struct {
	ID     int64
	UserID int64
	Stage  Stage
	SrcIP  string
	Expiry time.Time
}

type Manager struct {
	db *store.DB

	ttl  time.Duration
	idle time.Duration

	maxFailures int
	lockoutBase time.Duration
	lockoutMax  time.Duration

	// Failure counters live in memory on purpose: they must be cheap enough to
	// touch on every attempt, and losing them on restart is acceptable.
	mu       sync.Mutex
	failures map[string]*failure
}

type failure struct {
	count int
	until time.Time
}

type Options struct {
	TTL         time.Duration
	Idle        time.Duration
	MaxFailures int
	LockoutBase time.Duration
	LockoutMax  time.Duration
}

func NewManager(db *store.DB, o Options) *Manager {
	return &Manager{
		db:          db,
		ttl:         o.TTL,
		idle:        o.Idle,
		maxFailures: o.MaxFailures,
		lockoutBase: o.LockoutBase,
		lockoutMax:  o.LockoutMax,
		failures:    map[string]*failure{},
	}
}

/* -------------------------------------------------------------- lockout --- */

// Locked reports whether this key is currently barred, and for how long.
func (m *Manager) Locked(key string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.failures[key]
	if !ok || time.Now().After(f.until) {
		return false, 0
	}
	return true, time.Until(f.until)
}

// Fail records a failed attempt and backs off exponentially.
func (m *Manager) Fail(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.failures[key]
	if !ok {
		f = &failure{}
		m.failures[key] = f
	}
	f.count++

	if f.count < m.maxFailures {
		return
	}

	// Double the wait for every attempt past the threshold, up to the cap.
	backoff := m.lockoutBase << min(f.count-m.maxFailures, 16)
	if backoff > m.lockoutMax || backoff <= 0 {
		backoff = m.lockoutMax
	}
	f.until = time.Now().Add(backoff)
}

// Succeed clears the counter after a genuine login.
func (m *Manager) Succeed(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, key)
}

// SweepLockouts drops entries that have aged out.
func (m *Manager) SweepLockouts() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for k, f := range m.failures {
		if f.until.IsZero() || now.After(f.until.Add(time.Hour)) {
			delete(m.failures, k)
		}
	}
}

/* ------------------------------------------------------------- password --- */

// CheckPassword verifies credentials without leaking which half was wrong.
func (m *Manager) CheckPassword(ctx context.Context, username, password, srcIP string) (*store.User, error) {
	if locked, _ := m.Locked("ip:" + srcIP); locked {
		return nil, ErrLockedOut
	}
	if locked, _ := m.Locked("user:" + username); locked {
		return nil, ErrLockedOut
	}

	u, err := m.db.UserByName(ctx, username)
	if err != nil {
		// Spend the same time as a real verification so the response cannot be
		// used to tell existing accounts from missing ones.
		crypto.SpendVerifyTime(password)
		m.Fail("ip:" + srcIP)
		return nil, ErrBadPassword
	}

	if err := crypto.VerifyPassword(password, u.PasswordHash); err != nil {
		m.Fail("ip:" + srcIP)
		m.Fail("user:" + username)
		return nil, ErrBadPassword
	}
	if !u.IsActive() {
		// Same cost and same error as a wrong password: whether an account is
		// disabled is not something a stranger should be able to probe for.
		return nil, ErrBadPassword
	}
	return u, nil
}

/* -------------------------------------------------------------- session --- */

// Start creates a session and returns the raw token, which is shown to the
// browser exactly once. Only its hash is stored.
func (m *Manager) Start(ctx context.Context, userID int64, stage Stage, srcIP, userAgent string) (token string, err error) {
	token, err = crypto.RandomToken(32)
	if err != nil {
		return "", err
	}

	now := time.Now()
	ttl := m.ttl
	if stage == StagePending {
		// The MFA step gets a short window of its own.
		ttl = 5 * time.Minute
	}

	_, err = m.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token_hash, src_ip, user_agent, created_at, expires_at, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, stageHash(token, stage), srcIP, userAgent,
		now.Unix(), now.Add(ttl).Unix(), now.Unix())
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// Promote swaps a pending session for a full one once MFA succeeds.
func (m *Manager) Promote(ctx context.Context, token string, userID int64, srcIP, userAgent string) (string, error) {
	if err := m.Destroy(ctx, token, StagePending); err != nil {
		return "", err
	}
	return m.Start(ctx, userID, StageFull, srcIP, userAgent)
}

// Lookup resolves a token, enforcing expiry, idle timeout and IP binding.
func (m *Manager) Lookup(ctx context.Context, token string, stage Stage, srcIP string) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}

	var (
		s        Session
		expires  int64
		lastSeen int64
	)
	err := m.db.QueryRowContext(ctx,
		`SELECT id, user_id, src_ip, expires_at, last_seen FROM sessions WHERE token_hash = ?`,
		stageHash(token, stage)).
		Scan(&s.ID, &s.UserID, &s.SrcIP, &expires, &lastSeen)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("look up session: %w", err)
	}

	now := time.Now()
	if now.Unix() > expires {
		m.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, s.ID)
		return nil, ErrNoSession
	}
	if m.idle > 0 && now.Sub(time.Unix(lastSeen, 0)) > m.idle {
		m.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, s.ID)
		return nil, ErrNoSession
	}

	// A stolen cookie is useless from another address.
	if s.SrcIP != srcIP {
		return nil, ErrNoSession
	}

	m.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id = ?`, now.Unix(), s.ID)

	s.Stage = stage
	s.Expiry = time.Unix(expires, 0)
	return &s, nil
}

func (m *Manager) Destroy(ctx context.Context, token string, stage Stage) error {
	if token == "" {
		return nil
	}
	_, err := m.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, stageHash(token, stage))
	if err != nil {
		return fmt.Errorf("destroy session: %w", err)
	}
	return nil
}

// DestroyAllForUser is what locking an account or resetting MFA must do.
func (m *Manager) DestroyAllForUser(ctx context.Context, userID int64) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("destroy user sessions: %w", err)
	}
	return nil
}

// stageHash binds the token to its stage, so a half-authenticated cookie can
// never be replayed as a full one.
func stageHash(token string, stage Stage) string {
	return crypto.HashToken(string(stage) + ":" + token)
}

/* ---------------------------------------------------------------- http --- */

// SetSessionCookie writes the session cookie with the strict attributes set.
func SetSessionCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName(secure),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// ClearSessionCookie expires both spellings, so signing out is complete
// whichever one the browser is holding.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	for _, name := range []string{SessionCookieName(true), SessionCookieName(false)} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// NewCSRFToken issues a double-submit token. It is deliberately readable by
// JavaScript — the browser echoes it back in a header, which an attacker on
// another origin cannot do.
func NewCSRFToken(w http.ResponseWriter, secure bool) (string, error) {
	tok, err := crypto.RandomToken(32)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName(secure),
		Value:    tok,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return tok, nil
}

// CheckCSRF compares the header against the cookie in constant time.
func CheckCSRF(r *http.Request) bool {
	// Safe methods change nothing, so they need no token.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	cookie := readCookie(r, csrfName)
	if cookie == "" {
		return false
	}
	return crypto.ConstantTimeEqualString(cookie, r.Header.Get(CSRFHeader))
}

// ClientIP returns the address a request really came from.
//
// Forwarded headers are honoured only when the immediate peer is a proxy the
// operator listed. Trusting them blindly would let anyone claim any source
// address and walk straight into somebody else's grant.
func ClientIP(r *http.Request, trusted []string) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)

	if len(trusted) == 0 || peer == nil || !isTrusted(peer, trusted) {
		return peer
	}

	// Right-most entry is the one our trusted proxy actually saw.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := splitAndTrim(xff)
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := net.ParseIP(parts[i]); ip != nil && !isTrusted(ip, trusted) {
				return ip
			}
		}
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		if ip := net.ParseIP(real); ip != nil {
			return ip
		}
	}
	return peer
}

func isTrusted(ip net.IP, trusted []string) bool {
	for _, t := range trusted {
		if _, cidr, err := net.ParseCIDR(t); err == nil {
			if cidr.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(t); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

func splitAndTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			for len(part) > 0 && (part[0] == ' ' || part[0] == '\t') {
				part = part[1:]
			}
			for len(part) > 0 && (part[len(part)-1] == ' ' || part[len(part)-1] == '\t') {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

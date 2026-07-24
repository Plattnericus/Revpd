package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/store"
)

/*
   First-run setup.

   These endpoints exist only while the gateway has no accounts. The moment the
   first administrator is created they stop answering — otherwise anyone who
   reached the portal could mint themselves an admin.

   The window is closed by the database, not by a flag: every handler counts
   the users table, and the creation itself happens inside a transaction that
   re-checks under the write lock. Two people racing to be first cannot both
   win.
*/

// SetupNeeded reports whether the gateway still has no accounts.
func (s *Server) setupNeeded(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	return n == 0, nil
}

// openDuringSetup guards the handlers that must stop working afterwards.
func (s *Server) openDuringSetup(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		needed, err := s.setupNeeded(r.Context())
		if err != nil {
			serverError(w, err)
			return
		}
		if !needed {
			// Deliberately the same answer as an unknown route: there is
			// nothing here to probe.
			fail(w, http.StatusNotFound, "not found")
			return
		}
		if !auth.CheckCSRF(r) {
			fail(w, http.StatusForbidden, "csrf token missing or wrong")
			return
		}
		h(w, r)
	})
}

// handleSetupStatus tells the UI whether to show the wizard. Safe to call at
// any time, which is why it is not behind openDuringSetup.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	needed, err := s.setupNeeded(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	// A CSRF token so the wizard's first POST has one to send.
	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	send(w, map[string]any{
		"setup_required": needed,
		"hostname":       s.cfg.Web.Hostname,
		"gateway":        s.gatewayAddr(),
		"csrf":           csrf,
	})
}

// handleSetupAdmin creates the first administrator and signs them in.
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}

	if req.Username == "" {
		fail(w, http.StatusBadRequest, "a username is required")
		return
	}
	if len(req.Password) < 12 {
		fail(w, http.StatusBadRequest, "the password must be at least 12 characters")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		serverError(w, err)
		return
	}

	id, err := s.createFirstAdmin(r.Context(), req.Username, req.DisplayName, hash)
	if errors.Is(err, errSetupClosed) {
		fail(w, http.StatusConflict, "an account already exists")
		return
	}
	if err != nil {
		fail(w, http.StatusConflict, "could not create the account")
		return
	}

	ip := s.clientIP(r)
	s.audit(r, audit.Entry{
		Actor: req.Username, Action: audit.ActionUserCreated, Object: req.Username,
		SrcIP: ip.String(), Detail: map[string]any{"via": "setup", "role": "admin"},
	})

	// Sign them straight in so the wizard can continue. The session is full
	// because there is no second factor to check yet — enrolling one is the
	// very next step, and until it exists nobody else can log in at all.
	tok, err := s.auth.Start(r.Context(), id, auth.StageFull, ip.String(), r.UserAgent())
	if err != nil {
		serverError(w, err)
		return
	}
	auth.SetSessionCookie(w, tok, s.cfg.Auth.SessionTTL, s.secure(r))
	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	send(w, map[string]any{"id": id, "csrf": csrf})
}

var errSetupClosed = errors.New("setup is already complete")

// createFirstAdmin inserts the account, re-checking under the write lock so a
// second request racing the first cannot also succeed.
func (s *Server) createFirstAdmin(ctx context.Context, username, display, hash string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin setup: %w", err)
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		return 0, errSetupClosed
	}

	if display == "" {
		display = username
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, display_name, password_hash, role, rdp_hint, status, created_at)
		 VALUES (?, ?, ?, 'admin', ?, 'active', ?)`,
		username, display, hash, username, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("create first admin: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

/* ---------------------------------------------------------- enrolment --- */

// handleEnrollStart mints a TOTP secret and a set of backup codes.
//
// Behind the normal session guard, so it also works later for someone who
// needs to re-enrol. The secret is stored immediately but the account is not
// usable for login until a code has been confirmed, which handleEnrollConfirm
// does — that way a mistyped QR scan cannot lock somebody out.
func (s *Server) handleEnrollStart(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	secret, uri, err := mfa.TOTP{Skew: s.cfg.Auth.TOTPSkew}.
		Enroll("Revpd ("+s.cfg.Web.Hostname+")", u.Username)
	if err != nil {
		serverError(w, err)
		return
	}

	enc, err := s.sealer.Seal(fmt.Sprintf("totp:%d", u.ID), []byte(secret))
	if err != nil {
		serverError(w, err)
		return
	}
	if err := s.db.SetTOTPSecret(r.Context(), u.ID, enc); err != nil {
		serverError(w, err)
		return
	}

	codes, err := s.regenerateBackupCodes(r.Context(), u.ID)
	if err != nil {
		serverError(w, err)
		return
	}

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionEnrollTOTP, SrcIP: s.clientIP(r).String(),
	})

	// The secret is returned exactly once, so it can be shown as a QR code.
	send(w, map[string]any{"secret": secret, "uri": uri, "backup_codes": codes})
}

// handleEnrollConfirm checks that the authenticator was actually set up.
func (s *Server) handleEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}

	u := userFrom(r.Context())
	if !s.verifySecondFactor(r.Context(), u, req.Code) {
		fail(w, http.StatusBadRequest, "that code is not valid — check the time on your phone and try again")
		return
	}

	send(w, map[string]any{"ok": true})
}

// regenerateBackupCodes replaces any existing codes with a fresh set.
func (s *Server) regenerateBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id = ?`, userID); err != nil {
		return nil, fmt.Errorf("clear old backup codes: %w", err)
	}

	n := s.cfg.Auth.BackupCodes
	if n <= 0 {
		return []string{}, nil
	}

	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := crypto.NewBackupCode()
		if err != nil {
			return nil, err
		}
		hash, err := crypto.HashPassword(crypto.NormalizeBackupCode(code))
		if err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, userID, hash); err != nil {
			return nil, fmt.Errorf("store backup code: %w", err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

/* ------------------------------------------------------------- target --- */

// handleSetupTarget adds the first machine and grants the caller access.
//
// Behind the normal admin guard rather than the setup window: by this point an
// administrator exists and is signed in, so the ordinary rules apply.
func (s *Server) handleSetupTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		MAC  string `json:"mac"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.IP == "" || req.MAC == "" {
		fail(w, http.StatusBadRequest, "name, IP address and MAC address are all required")
		return
	}

	id, err := s.db.CreateTarget(r.Context(), store.Target{Name: req.Name, IP: req.IP, MAC: req.MAC})
	if err != nil {
		fail(w, http.StatusConflict, "could not create the machine, the name may already be taken")
		return
	}

	u := userFrom(r.Context())
	if err := s.db.GrantTargetAccess(r.Context(), u.ID, id); err != nil {
		serverError(w, err)
		return
	}

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionTargetCreated, Object: req.Name,
		SrcIP: s.clientIP(r).String(), Detail: map[string]any{"via": "setup"},
	})

	send(w, map[string]any{"id": id})
}

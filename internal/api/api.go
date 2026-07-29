// Package api serves the web portal: REST endpoints plus a live status stream.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/netcheck"
	"github.com/plattnericus/revpd/internal/notify"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/update"
)

type Server struct {
	db     *store.DB
	log    *audit.Log
	cfg    config.Config
	auth   *auth.Manager
	engine *policy.Engine
	sealer *crypto.Sealer

	challenges *challengeStore

	// updates is nil where the binary cannot replace itself — in a container,
	// or when the operator turned it off.
	updates *update.Manager
	version string

	// portalAddr is where the portal actually ended up, which is not always
	// web.listen: the fallback moves it when the usual port is taken.
	portalAddr string

	// public knows how the gateway looks from the internet. Nil where nothing
	// is detected, which leaves the configured hostname to speak for itself.
	public *netcheck.Service

	// notifier sends events on to a phone or a chat channel. Held here so a
	// changed destination applies on save, and so the settings page can offer
	// to try it.
	notifier *notify.Notifier

	// fileCfg is the configuration as it came from revpd.yaml and the
	// environment, before anything stored in the database was layered on. The
	// settings page shows both so an override is visible as an override.
	fileCfg config.Config

	assets http.Handler
}

func New(db *store.DB, log *audit.Log, cfg config.Config, am *auth.Manager, engine *policy.Engine, sealer *crypto.Sealer, assets http.Handler) *Server {
	return &Server{
		db: db, log: log, cfg: cfg, auth: am, engine: engine, sealer: sealer,
		challenges: newChallengeStore(),
		assets:     assets,

		// Overwritten by WithFileConfig where the two differ. Defaulting to
		// the running configuration means an unconfigured server reports no
		// spurious overrides.
		fileCfg: cfg,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public: everything needed to get logged in.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/mfa", s.handleMFA)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// First-run setup. The status endpoint answers always; creating the first
	// administrator only works while there are no accounts at all.
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.Handle("POST /api/setup/admin", s.openDuringSetup(s.handleSetupAdmin))

	// The remaining setup steps run as the administrator who was just created.
	mux.Handle("POST /api/setup/enroll", s.authed(s.handleEnrollStart))
	mux.Handle("POST /api/setup/enroll/confirm", s.authed(s.handleEnrollConfirm))
	mux.Handle("POST /api/setup/target", s.admin(s.handleSetupTarget))
	mux.Handle("POST /api/setup/complete", s.authed(s.handleSetupComplete))

	// Passkeys. Login is public by necessity; registration needs a session.
	mux.HandleFunc("POST /api/passkey/login/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("POST /api/passkey/login/finish", s.handlePasskeyLoginFinish)
	mux.Handle("GET /api/passkey", s.authed(s.handlePasskeyList))
	mux.Handle("POST /api/passkey/register/begin", s.authed(s.handlePasskeyRegisterBegin))
	mux.Handle("POST /api/passkey/register/finish", s.authed(s.handlePasskeyRegisterFinish))
	mux.Handle("DELETE /api/passkey/{id}", s.authed(s.handlePasskeyDelete))

	// Authenticated.
	mux.Handle("GET /api/me", s.authed(s.handleMe))
	mux.Handle("GET /api/targets", s.authed(s.handleTargets))
	mux.Handle("POST /api/targets/{id}/unlock", s.authed(s.handleUnlock))
	mux.Handle("GET /api/targets/{id}/rdpfile", s.authed(s.handleRDPFile))
	mux.Handle("GET /api/events", s.authed(s.handleEvents))
	mux.Handle("GET /api/sessions", s.authed(s.handleSessions))
	mux.Handle("GET /api/audit", s.authed(s.handleAudit))

	// Admin only.
	mux.Handle("GET /api/admin/users", s.admin(s.handleListUsers))
	mux.Handle("POST /api/admin/users", s.admin(s.handleCreateUser))
	mux.Handle("POST /api/admin/users/{id}/status", s.admin(s.handleUserStatus))
	mux.Handle("POST /api/admin/users/{id}/targets", s.admin(s.handleUserTargets))
	mux.Handle("GET /api/admin/targets", s.admin(s.handleListTargets))
	mux.Handle("POST /api/admin/targets", s.admin(s.handleCreateTarget))
	mux.Handle("POST /api/admin/targets/{id}/testwol", s.admin(s.handleTestWoL))
	mux.Handle("GET /api/admin/settings", s.admin(s.handleSettings))

	// Everything that can be changed here, what it is set to, and what the
	// file says. Saving validates the whole set before storing any of it.
	mux.Handle("GET /api/admin/config", s.admin(s.handleSettingsSchema))
	mux.Handle("POST /api/admin/config", s.admin(s.handleSettingsSave))
	mux.Handle("POST /api/admin/restart", s.admin(s.handleRestart))

	// Sending a real notification to whatever is configured. A button beats
	// waiting for the next lockout to find out the URL had a typo in it.
	mux.Handle("POST /api/admin/notify/test", s.admin(s.handleNotifyTest))

	// How the gateway is reached from outside. Reading is enough to draw the
	// connect address; looking again reaches out to a third party and opens
	// connections, so that stays an administrator's decision.
	mux.Handle("GET /api/admin/network", s.admin(s.handleNetwork))
	mux.Handle("POST /api/admin/network/check", s.admin(s.handleNetworkCheck))

	// Finding machines to add. Scanning reaches out to the local network, so
	// it is an administrator's decision and nobody else's.
	mux.Handle("GET /api/admin/discover/ranges", s.admin(s.handleDiscoverRanges))
	mux.Handle("POST /api/admin/discover/scan", s.admin(s.handleDiscoverScan))
	mux.Handle("POST /api/admin/discover/host", s.admin(s.handleDiscoverHost))

	// Updates. Reading the status is enough to draw the banner; everything
	// that downloads or installs is an administrator's decision.
	mux.Handle("GET /api/update", s.authed(s.handleUpdateStatus))
	mux.Handle("POST /api/admin/update/check", s.admin(s.handleUpdateCheck))
	mux.Handle("POST /api/admin/update/install", s.admin(s.handleUpdateInstall))
	mux.Handle("POST /api/admin/update/settings", s.admin(s.handleUpdateSettings))

	if s.assets != nil {
		mux.Handle("/", s.assets)
	}

	return s.withAccessLog(s.withSecurityHeaders(mux))
}

/* ---------------------------------------------------------- middleware --- */

type ctxKey string

const userKey ctxKey = "user"

func userFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userKey).(*store.User)
	return u
}

// authed requires a fully authenticated session and a valid CSRF token.
func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.CheckCSRF(r) {
			fail(w, http.StatusForbidden, "csrf token missing or wrong")
			return
		}

		ip := s.clientIP(r)
		sess, err := s.auth.Lookup(r.Context(), auth.SessionToken(r), auth.StageFull, ip.String())
		if err != nil {
			fail(w, http.StatusUnauthorized, "not signed in")
			return
		}

		u, err := s.db.UserByID(r.Context(), sess.UserID)
		if err != nil || !u.IsActive() {
			fail(w, http.StatusUnauthorized, "account is not active")
			return
		}

		noteRequestUser(r.Context(), u.Username)
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

func (s *Server) admin(h http.HandlerFunc) http.Handler {
	inner := s.authed(func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).IsAdmin() {
			fail(w, http.StatusForbidden, "administrator role required")
			return
		}
		h(w, r)
	})
	return inner
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// The UI ships no inline scripts and loads nothing from third parties,
		// so the policy can stay this tight.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")

		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) net.IP {
	return auth.ClientIP(r, s.cfg.Web.TrustedProxies)
}

// secure reflects whether cookies may carry the Secure attribute. On plain
// HTTP during local development they cannot, or the browser drops them.
func (s *Server) secure(r *http.Request) bool {
	return r.TLS != nil || s.cfg.Web.ACME || s.cfg.Web.TLSCert != ""
}

/* ------------------------------------------------------------- session --- */

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}

	ip := s.clientIP(r)
	u, err := s.auth.CheckPassword(r.Context(), req.Username, req.Password, ip.String())

	if errors.Is(err, auth.ErrLockedOut) {
		s.audit(r, audit.Entry{Actor: req.Username, Action: audit.ActionLockout, SrcIP: ip.String()})
		fail(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	if err != nil {
		s.audit(r, audit.Entry{Actor: req.Username, Action: audit.ActionLoginFail, SrcIP: ip.String()})
		// Same message either way: never reveal whether the account exists.
		fail(w, http.StatusUnauthorized, "wrong username or password")
		return
	}

	s.audit(r, audit.Entry{Actor: u.Username, Action: audit.ActionLoginOK, SrcIP: ip.String()})

	// Nothing enrolled. What happens next is a deliberate choice made in the
	// configuration, not something to decide here.
	if len(u.TOTPSecretEnc) == 0 && !s.hasBackupCodes(r.Context(), u) {
		if s.cfg.Auth.RequireSecondFactor {
			s.audit(r, audit.Entry{
				Actor: u.Username, Action: audit.ActionLoginFail, SrcIP: ip.String(),
				Detail: map[string]any{"reason": "no second factor enrolled"},
			})
			fail(w, http.StatusForbidden,
				"this account has no second factor set up, and one is required. "+
					"Set it up under Settings, or ask an administrator to turn the requirement off.")
			return
		}

		// Allowed through on the password alone. Recorded as such: an audit
		// trail that cannot tell one factor from two is not much of a trail.
		full, err := s.auth.Start(r.Context(), u.ID, auth.StageFull, ip.String(), r.UserAgent())
		if err != nil {
			serverError(w, err)
			return
		}
		s.audit(r, audit.Entry{
			Actor: u.Username, Action: audit.ActionLoginOK, SrcIP: ip.String(),
			Detail: map[string]any{"second_factor": false},
		})

		auth.SetSessionCookie(w, full, s.cfg.Auth.SessionTTL, s.secure(r))
		csrf, _ := auth.NewCSRFToken(w, s.secure(r))
		send(w, map[string]any{"stage": "full", "csrf": csrf})
		return
	}

	tok, err := s.auth.Start(r.Context(), u.ID, auth.StagePending, ip.String(), r.UserAgent())
	if err != nil {
		serverError(w, err)
		return
	}
	auth.SetSessionCookie(w, tok, 5*time.Minute, s.secure(r))
	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	send(w, map[string]any{"stage": "mfa", "methods": s.methodsFor(u), "csrf": csrf})
}

func (s *Server) methodsFor(u *store.User) []string {
	m := []string{}
	if len(u.TOTPSecretEnc) > 0 {
		m = append(m, "totp")
	}
	if s.hasBackupCodes(context.Background(), u) {
		m = append(m, "backup")
	}
	return m
}

func (s *Server) hasBackupCodes(ctx context.Context, u *store.User) bool {
	n, err := s.db.CountBackupCodes(ctx, u.ID)
	return err == nil && n > 0
}

func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) {
	if !auth.CheckCSRF(r) {
		fail(w, http.StatusForbidden, "csrf token missing or wrong")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}

	ip := s.clientIP(r)
	token := auth.SessionToken(r)

	sess, err := s.auth.Lookup(r.Context(), token, auth.StagePending, ip.String())
	if err != nil {
		fail(w, http.StatusUnauthorized, "login step expired, start again")
		return
	}

	u, err := s.db.UserByID(r.Context(), sess.UserID)
	if err != nil || !u.IsActive() {
		fail(w, http.StatusUnauthorized, "account is not active")
		return
	}

	if locked, _ := s.auth.Locked("mfa:" + u.Username); locked {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}

	if ok := s.verifySecondFactor(r.Context(), u, req.Code); !ok {
		s.auth.Fail("mfa:" + u.Username)
		s.auth.Fail("ip:" + ip.String())
		s.audit(r, audit.Entry{Actor: u.Username, Action: audit.ActionMFAFail, SrcIP: ip.String()})
		fail(w, http.StatusUnauthorized, "code is not valid")
		return
	}

	s.auth.Succeed("mfa:" + u.Username)
	s.auth.Succeed("ip:" + ip.String())
	s.audit(r, audit.Entry{Actor: u.Username, Action: audit.ActionMFAOK, SrcIP: ip.String()})

	full, err := s.auth.Promote(r.Context(), token, u.ID, ip.String(), r.UserAgent())
	if err != nil {
		serverError(w, err)
		return
	}
	auth.SetSessionCookie(w, full, s.cfg.Auth.SessionTTL, s.secure(r))
	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	send(w, map[string]any{"stage": "full", "csrf": csrf})
}

// verifySecondFactor accepts a TOTP code or a backup code.
func (s *Server) verifySecondFactor(ctx context.Context, u *store.User, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}

	// Backup codes are longer and carry a dash, so the shape tells them apart.
	if len(crypto.NormalizeBackupCode(code)) == 10 && strings.ContainsAny(code, "-ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjklmnpqrstuvwxyz") {
		return s.consumeBackupCode(ctx, u, code)
	}

	if len(u.TOTPSecretEnc) == 0 {
		return false
	}
	secret, err := s.sealer.Open(fmt.Sprintf("totp:%d", u.ID), u.TOTPSecretEnc)
	if err != nil {
		slog.Error("could not decrypt totp secret", "user", u.Username, "err", err)
		return false
	}

	counter, err := mfa.TOTP{Skew: s.cfg.Auth.TOTPSkew}.Verify(string(secret), code, u.TOTPLastCounter, time.Now())
	if err != nil {
		return false
	}

	// Claim the step, and only accept the login if this call burned it. Two
	// requests arriving with the same code both pass Verify, so the database
	// decides which one is the replay.
	if err := s.db.ClaimTOTPCounter(ctx, u.ID, counter); err != nil {
		if !errors.Is(err, store.ErrCounterAlreadyUsed) {
			slog.Error("could not record totp counter", "user", u.Username, "err", err)
		}
		return false
	}
	return true
}

func (s *Server) consumeBackupCode(ctx context.Context, u *store.User, code string) bool {
	norm := crypto.NormalizeBackupCode(code)

	// Read and close before writing: the pool holds one connection, so an
	// UPDATE issued mid-query would wait on the connection the query holds.
	codes, err := s.db.OpenBackupCodes(ctx, u.ID)
	if err != nil {
		return false
	}

	for _, c := range codes {
		if crypto.VerifyPassword(norm, c.Hash) != nil {
			continue
		}
		// Claim it in the same statement that checks it, so two parallel
		// requests cannot both spend the same code.
		return s.db.ClaimBackupCode(ctx, c.ID) == nil
	}
	return false
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := auth.SessionToken(r)
	s.auth.Destroy(r.Context(), tok, auth.StageFull)
	s.auth.Destroy(r.Context(), tok, auth.StagePending)
	auth.ClearSessionCookie(w, s.secure(r))
	send(w, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	send(w, map[string]any{
		"username":      u.Username,
		"display_name":  u.DisplayName,
		"role":          u.Role,
		"totp_enrolled": len(u.TOTPSecretEnc) > 0,
	})
}

/* ------------------------------------------------------------- targets --- */

type targetView struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	RDPPort      int    `json:"rdp_port"`
	MAC          string `json:"mac"`
	WoLBroadcast string `json:"wol_broadcast"`
	BootTimeoutS int    `json:"boot_timeout_s"`
	Notes        string `json:"notes"`
	State        string `json:"state"`
}

func (s *Server) view(ctx context.Context, t store.Target) targetView {
	return targetView{
		ID: t.ID, Name: t.Name, Hostname: t.Hostname, IP: t.IP, RDPPort: t.RDPPort,
		MAC: t.MAC, WoLBroadcast: t.WoLBroadcast, BootTimeoutS: t.BootTimeoutS,
		Notes: t.Notes, State: s.engine.Status(ctx, &t),
	}
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.db.ListTargetsForUser(r.Context(), userFrom(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}

	out := make([]targetView, 0, len(targets))
	for _, t := range targets {
		out = append(out, s.view(r.Context(), t))
	}
	send(w, map[string]any{"targets": out, "gateway": s.gatewayAddr(r.Context())})
}

// gatewayAddr is what the user types into mstsc.
//
// Derived from configuration and detection, never guessed from the request, so
// it stays correct behind a proxy — and so a page served over the LAN still
// prints the address that works from outside, which is the one worth having.
func (s *Server) gatewayAddr(ctx context.Context) string {
	return s.publicGateway(ctx)
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	u := userFrom(r.Context())
	ip := s.clientIP(r)

	target, grantID, err := s.engine.Unlock(r.Context(), u, id, ip)
	if err != nil {
		fail(w, http.StatusForbidden, "not allowed to reach this target")
		return
	}

	send(w, map[string]any{
		"grant_id":   grantID,
		"expires_in": int(s.cfg.Grant.TTL.Seconds()),
		"gateway":    s.gatewayAddr(r.Context()),
		"target":     s.view(r.Context(), *target),
	})
}

// handleRDPFile hands back a ready-made connection file.
func (s *Server) handleRDPFile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	u := userFrom(r.Context())
	allowed, err := s.db.CanReach(r.Context(), u, id)
	if err != nil || !allowed {
		fail(w, http.StatusForbidden, "not allowed to reach this target")
		return
	}

	t, err := s.db.TargetByID(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "target not found")
		return
	}

	// The file carries the port explicitly rather than letting the client
	// assume 3389: the whole point of forwarding some other port on the router
	// is that the assumption is wrong. Joined properly, so an IPv6 address
	// comes out bracketed instead of turning into nonsense.
	cfg := s.wantedConfig(r.Context())
	host := net.JoinHostPort(s.publicHost(cfg), strconv.Itoa(cfg.PublicRDPPort()))

	// CRLF and a .rdp filename, or mstsc will not open it.
	body := strings.Join([]string{
		"full address:s:" + host,
		"username:s:" + u.Username,
		"prompt for credentials:i:1",
		"authentication level:i:2",
		"redirectclipboard:i:1",
		"audiomode:i:0",
		"screen mode id:i:2",
		"",
	}, "\r\n")

	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeFilename(t.Name)+".rdp"))
	w.Write([]byte(body))
}

func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "connection"
	}
	return b.String()
}

/* -------------------------------------------------------------- events --- */

// handleEvents streams target status so the dashboard can show a live wake.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx would buffer this otherwise
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	u := userFrom(r.Context())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	push := func() bool {
		targets, err := s.db.ListTargetsForUser(r.Context(), u)
		if err != nil {
			return false
		}

		out := make([]targetView, 0, len(targets))
		for _, t := range targets {
			out = append(out, s.view(r.Context(), t))
		}

		payload, err := json.Marshal(map[string]any{"targets": out})
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: targets\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !push() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

/* -------------------------------------------------- sessions and audit --- */

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	live, err := s.db.ListLiveSessions(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	u := userFrom(r.Context())
	out := []map[string]any{}
	for _, l := range live {
		// Ordinary users only see their own connections.
		if !u.IsAdmin() && l.Username != u.Username {
			continue
		}
		out = append(out, map[string]any{
			"id": l.ID, "user": l.Username, "target": l.Target,
			"src_ip": l.SrcIP, "started_at": l.StartedAt.UTC().Format(time.RFC3339),
		})
	}
	send(w, map[string]any{"sessions": out})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	q := audit.Query{
		Action: r.URL.Query().Get("action"),
		Limit:  atoiDefault(r.URL.Query().Get("limit"), 100),
	}
	if !u.IsAdmin() {
		q.Actor = u.Username // no peeking at other people's history
	}

	entries, err := s.log.List(r.Context(), q)
	if err != nil {
		serverError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"id": e.ID, "ts": e.TS.UTC().Format(time.RFC3339), "actor": e.Actor,
			"action": e.Action, "object": e.Object, "src_ip": e.SrcIP, "detail": e.Detail,
		})
	}

	resp := map[string]any{"entries": out}
	if u.IsAdmin() {
		brk, n, err := s.log.Verify(r.Context())
		resp["chain"] = map[string]any{
			"intact": err == nil && brk == nil,
			"count":  n,
		}
	}
	send(w, resp)
}

/* --------------------------------------------------------------- admin --- */

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		var targetIDs []int64
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT target_id FROM user_targets WHERE user_id = ?`, u.ID)
		if err == nil {
			for rows.Next() {
				var id int64
				rows.Scan(&id)
				targetIDs = append(targetIDs, id)
			}
			rows.Close()
		}
		if targetIDs == nil {
			targetIDs = []int64{}
		}

		out = append(out, map[string]any{
			"id": u.ID, "username": u.Username, "display_name": u.DisplayName,
			"role": u.Role, "status": u.Status, "rdp_hint": u.RDPHint,
			"totp_enrolled": len(u.TOTPSecretEnc) > 0, "target_ids": targetIDs,
		})
	}
	send(w, map[string]any{"users": out})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		RDPHint     string `json:"rdp_hint"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Username == "" || len(req.Password) < 12 {
		fail(w, http.StatusBadRequest, "username required and password must be at least 12 characters")
		return
	}
	if req.Role != "admin" {
		req.Role = "user"
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		serverError(w, err)
		return
	}

	id, err := s.db.CreateUser(r.Context(), store.User{
		Username: req.Username, DisplayName: req.DisplayName,
		PasswordHash: hash, Role: req.Role, RDPHint: req.RDPHint,
	})
	if err != nil {
		fail(w, http.StatusConflict, "could not create user, the name may already exist")
		return
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionUserCreated,
		Object: req.Username, SrcIP: s.clientIP(r).String(),
	})
	send(w, map[string]any{"id": id})
}

func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	switch req.Status {
	case "active", "locked", "disabled":
	default:
		fail(w, http.StatusBadRequest, "status must be active, locked or disabled")
		return
	}

	if err := s.db.SetUserStatus(r.Context(), id, req.Status); err != nil {
		serverError(w, err)
		return
	}

	// Locking has to bite now, not when the session happens to expire.
	if req.Status != "active" {
		s.auth.DestroyAllForUser(r.Context(), id)
		s.db.RevokeGrantsForUser(r.Context(), id)
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionUserUpdated,
		SrcIP: s.clientIP(r).String(), Detail: map[string]any{"user_id": id, "status": req.Status},
	})
	send(w, map[string]any{"ok": true})
}

func (s *Server) handleUserTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var req struct {
		TargetIDs []int64 `json:"target_ids"`
	}
	if !decode(w, r, &req) {
		return
	}

	current, err := s.db.ListTargets(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	wanted := map[int64]bool{}
	for _, t := range req.TargetIDs {
		wanted[t] = true
	}
	for _, t := range current {
		if wanted[t.ID] {
			s.db.GrantTargetAccess(r.Context(), id, t.ID)
		} else {
			s.db.RevokeTargetAccess(r.Context(), id, t.ID)
		}
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionUserUpdated,
		SrcIP: s.clientIP(r).String(), Detail: map[string]any{"user_id": id, "targets": req.TargetIDs},
	})
	send(w, map[string]any{"ok": true})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.db.ListTargets(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	out := make([]targetView, 0, len(targets))
	for _, t := range targets {
		out = append(out, s.view(r.Context(), t))
	}
	send(w, map[string]any{"targets": out})
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Hostname     string `json:"hostname"`
		IP           string `json:"ip"`
		RDPPort      int    `json:"rdp_port"`
		MAC          string `json:"mac"`
		WoLBroadcast string `json:"wol_broadcast"`
		BootTimeoutS int    `json:"boot_timeout_s"`
		Notes        string `json:"notes"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || (req.IP == "" && req.Hostname == "") {
		fail(w, http.StatusBadRequest, "name and either an IP or a hostname are required")
		return
	}

	id, err := s.db.CreateTarget(r.Context(), store.Target{
		Name: req.Name, Hostname: req.Hostname, IP: req.IP, RDPPort: req.RDPPort,
		MAC: req.MAC, WoLBroadcast: req.WoLBroadcast, BootTimeoutS: req.BootTimeoutS,
		Notes: req.Notes,
	})
	if err != nil {
		fail(w, http.StatusConflict, "could not create target, the name may already exist")
		return
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionTargetCreated,
		Object: req.Name, SrcIP: s.clientIP(r).String(),
	})
	send(w, map[string]any{"id": id})
}

func (s *Server) handleTestWoL(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	t, err := s.db.TargetByID(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "target not found")
		return
	}
	if err := s.engine.TestWake(r.Context(), t); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionWolSent,
		Object: t.Name, SrcIP: s.clientIP(r).String(), Detail: map[string]any{"test": true},
	})
	send(w, map[string]any{"ok": true})
}

// handleSettings exposes the running configuration. Secrets never appear here.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	send(w, map[string]any{
		"hostname":           s.cfg.Web.Hostname,
		"relay_listen":       s.cfg.Relay.Listen,
		"gateway":            s.gatewayAddr(r.Context()),
		"grant_ttl_s":        int(s.cfg.Grant.TTL.Seconds()),
		"reuse_window_s":     int(s.cfg.Grant.ReuseWindow.Seconds()),
		"jit_enabled":        s.cfg.JIT.Enabled,
		"jit_hold_timeout_s": int(s.cfg.JIT.HoldTimeout.Seconds()),
		"max_failures":       s.cfg.Auth.MaxFailures,
		"tarpit_s":           int(s.cfg.Relay.Tarpit.Seconds()),
		"max_conns_per_ip":   s.cfg.Relay.MaxConnsPerIP,
		"rdgw_enabled":       s.cfg.RDGW.Enabled,
	})
}

/* --------------------------------------------------------------- utils --- */

func (s *Server) audit(r *http.Request, e audit.Entry) {
	if err := s.log.Append(r.Context(), e); err != nil {
		slog.Error("audit append failed", "action", e.Action, "err", err)
	}
}

func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	// Cap the body: no endpoint here needs more, and it stops a trivial DoS.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func send(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// serverError logs the detail and tells the client nothing useful.
func serverError(w http.ResponseWriter, err error) {
	slog.Error("request failed", "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/mfa/webauthn"
	"github.com/plattnericus/revpd/internal/store"
)

/*
   Passkeys.

   Challenges live in memory rather than the database: they are valid for two
   minutes, are worthless once used, and losing them on restart costs a retry.
   Keyed by source address so one browser cannot consume another's.
*/

const challengeTTL = 2 * time.Minute

type challengeStore struct {
	mu    sync.Mutex
	items map[string]*webauthn.Challenge
}

func newChallengeStore() *challengeStore {
	return &challengeStore{items: map[string]*webauthn.Challenge{}}
}

func (c *challengeStore) put(key string, ch *webauthn.Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistic sweep; the map only ever holds pending logins.
	for k, v := range c.items {
		if v.Expired() {
			delete(c.items, k)
		}
	}
	c.items[key] = ch
}

// take removes and returns a challenge. One use only, so a captured response
// cannot be replayed.
func (c *challengeStore) take(key string) *webauthn.Challenge {
	c.mu.Lock()
	defer c.mu.Unlock()

	ch := c.items[key]
	delete(c.items, key)
	return ch
}

// webauthnConfig derives the relying party from the configured hostname.
//
// It has to match what the browser reports exactly, so the origin is rebuilt
// from the request rather than guessed — a mismatch is the single most common
// reason passkeys silently stop working.
func (s *Server) webauthnConfig(r *http.Request) webauthn.Config {
	scheme := "http"
	if s.secure(r) {
		scheme = "https"
	}

	origin := scheme + "://" + r.Host
	return webauthn.Config{
		RPID:        hostOnly(r.Host),
		Origin:      origin,
		DisplayName: "Revpd",
	}
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

/* ------------------------------------------------------- registration --- */

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	ch, err := webauthn.NewChallenge(u.ID, challengeTTL)
	if err != nil {
		serverError(w, err)
		return
	}

	existing, err := s.db.PasskeysFor(r.Context(), u.ID)
	if err != nil {
		serverError(w, err)
		return
	}
	ids := make([][]byte, 0, len(existing))
	for _, p := range existing {
		ids = append(ids, p.CredentialID)
	}

	s.challenges.put(challengeKey("reg", u.ID, s.clientIP(r)), ch)

	display := u.DisplayName
	if display == "" {
		display = u.Username
	}

	send(w, s.webauthnConfig(r).BeginRegistration(ch, u.ID, u.Username, display, ids))
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	var req struct {
		Name       string                          `json:"name"`
		Credential webauthn.RegistrationResponse   `json:"credential"`
	}
	if !decode(w, r, &req) {
		return
	}

	ch := s.challenges.take(challengeKey("reg", u.ID, s.clientIP(r)))
	cred, err := s.webauthnConfig(r).FinishRegistration(ch, req.Credential)
	if err != nil {
		fail(w, http.StatusBadRequest, "the passkey could not be verified")
		return
	}

	name := req.Name
	if name == "" {
		name = "Passkey"
	}

	if _, err := s.db.AddPasskey(r.Context(), store.Passkey{
		UserID:       u.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		Name:         name,
	}); err != nil {
		fail(w, http.StatusConflict, "this passkey is already registered")
		return
	}

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionEnrollPasskey,
		SrcIP: s.clientIP(r).String(), Detail: map[string]any{"name": name},
	})
	send(w, map[string]any{"ok": true, "name": name})
}

func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	keys, err := s.db.PasskeysFor(r.Context(), u.ID)
	if err != nil {
		serverError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(keys))
	for _, p := range keys {
		out = append(out, map[string]any{
			"id": p.ID, "name": p.Name, "created_at": p.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	send(w, map[string]any{"passkeys": out})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	u := userFrom(r.Context())

	// Removing the last factor would lock the account out of the portal, and
	// on the RDP path there would be nothing left to check at all.
	if len(u.TOTPSecretEnc) == 0 {
		n, err := s.db.CountPasskeys(r.Context(), u.ID)
		if err == nil && n <= 1 {
			fail(w, http.StatusConflict, "this is the only second factor left — set up an authenticator app first")
			return
		}
	}

	if err := s.db.DeletePasskey(r.Context(), u.ID, id); err != nil {
		serverError(w, err)
		return
	}
	send(w, map[string]any{"ok": true})
}

/* -------------------------------------------------------------- login --- */

// handlePasskeyLoginBegin starts a passkey login.
//
// Deliberately does not say whether the account exists: a challenge comes back
// either way, and a stranger learns nothing from asking.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &req) {
		return
	}

	ip := s.clientIP(r)

	var allowed [][]byte
	var userID int64

	if u, err := s.db.UserByName(r.Context(), req.Username); err == nil && u.IsActive() {
		userID = u.ID
		if keys, err := s.db.PasskeysFor(r.Context(), u.ID); err == nil {
			for _, p := range keys {
				allowed = append(allowed, p.CredentialID)
			}
		}
	}

	ch, err := webauthn.NewChallenge(userID, challengeTTL)
	if err != nil {
		serverError(w, err)
		return
	}
	s.challenges.put(challengeKey("login", 0, ip), ch)

	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	opts := s.webauthnConfig(r).BeginAssertion(ch, allowed)
	send(w, map[string]any{"options": opts, "csrf": csrf})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !auth.CheckCSRF(r) {
		fail(w, http.StatusForbidden, "csrf token missing or wrong")
		return
	}

	var req struct {
		Credential webauthn.AssertionResponse `json:"credential"`
	}
	if !decode(w, r, &req) {
		return
	}

	ip := s.clientIP(r)

	if locked, _ := s.auth.Locked("ip:" + ip.String()); locked {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}

	ch := s.challenges.take(challengeKey("login", 0, ip))

	rawID, err := decodeCredentialID(req.Credential.RawID, req.Credential.ID)
	if err != nil {
		s.auth.Fail("ip:" + ip.String())
		fail(w, http.StatusUnauthorized, "the passkey could not be verified")
		return
	}

	key, err := s.db.PasskeyByCredentialID(r.Context(), rawID)
	if err != nil {
		s.auth.Fail("ip:" + ip.String())
		fail(w, http.StatusUnauthorized, "the passkey could not be verified")
		return
	}

	count, err := s.webauthnConfig(r).FinishAssertion(ch, req.Credential, key.PublicKey, key.SignCount)
	if err != nil {
		s.auth.Fail("ip:" + ip.String())
		s.audit(r, audit.Entry{Action: audit.ActionMFAFail, SrcIP: ip.String(), Detail: map[string]any{"via": "passkey"}})
		fail(w, http.StatusUnauthorized, "the passkey could not be verified")
		return
	}

	u, err := s.db.UserByID(r.Context(), key.UserID)
	if err != nil || !u.IsActive() {
		fail(w, http.StatusUnauthorized, "account is not active")
		return
	}

	// Record the advanced counter before the login counts, so a clone that
	// races us cannot also succeed.
	if err := s.db.UpdateSignCount(r.Context(), key.ID, count); err != nil {
		serverError(w, err)
		return
	}

	s.auth.Succeed("ip:" + ip.String())
	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionMFAOK, SrcIP: ip.String(),
		Detail: map[string]any{"via": "passkey", "key": key.Name},
	})

	// A passkey is both factors at once: possession of the authenticator plus
	// whatever unlocked it. No password step is owed.
	tok, err := s.auth.Start(r.Context(), u.ID, auth.StageFull, ip.String(), r.UserAgent())
	if err != nil {
		serverError(w, err)
		return
	}
	auth.SetSessionCookie(w, tok, s.cfg.Auth.SessionTTL, s.secure(r))
	csrf, _ := auth.NewCSRFToken(w, s.secure(r))

	send(w, map[string]any{"stage": "full", "csrf": csrf})
}

// decodeCredentialID takes whichever of rawId or id the browser filled in.
func decodeCredentialID(rawID, id string) ([]byte, error) {
	if rawID != "" {
		return webauthn.DecodeB64(rawID)
	}
	return webauthn.DecodeB64(id)
}

func challengeKey(kind string, userID int64, ip net.IP) string {
	return kind + ":" + ip.String() + ":" + itoa(userID)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

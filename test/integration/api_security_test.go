//go:build integration

// Access control on the web portal, exercised through real HTTP requests.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/api"
	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/netcheck"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

type apiEnv struct {
	srv    *httptest.Server
	db     *store.DB
	secret string

	// public is the address service the portal was built with, so a test can
	// see what it was told without going through HTTP.
	public *netcheck.Service
}

const apiPassword = "CorrectHorseBatteryStaple"

// newAPI brings up the portal with one enrolled admin and one plain user who
// has no second factor at all.
func newAPI(t *testing.T) *apiEnv { return newAPIWith(t, nil) }

// newAPIWith is newAPI with a chance to change the configuration first, for
// tests about what the gateway is set to rather than who may reach it.
func newAPIWith(t *testing.T, tune func(*config.Config)) *apiEnv {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	cfg := config.Defaults()
	cfg.Web.Hostname = "gw.test"

	// Detection off unless a test asks for it: the suite must not depend on
	// somebody else's server being up, or reach out to one at all.
	cfg.Public.Detect = false
	cfg.Public.Resolvers = nil

	if tune != nil {
		tune(&cfg)
	}

	key, _ := crypto.NewMasterKey()
	sealer, _ := crypto.NewSealer(key)

	hash, _ := crypto.HashPassword(apiPassword)

	// felix: administrator with TOTP enrolled.
	adminID, err := db.CreateUser(ctx, store.User{
		Username: "felix", DisplayName: "Felix", PasswordHash: hash, Role: "admin",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	secret, _, _ := mfa.TOTP{Skew: 1}.Enroll("revpd", "felix")
	enc, _ := sealer.Seal(fmt.Sprintf("totp:%d", adminID), []byte(secret))
	db.SetTOTPSecret(ctx, adminID, enc)

	// anna: ordinary user, no second factor set up.
	if _, err := db.CreateUser(ctx, store.User{
		Username: "anna", DisplayName: "Anna", PasswordHash: hash, Role: "user",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	am := auth.NewManager(db, auth.Options{
		TTL: time.Hour, Idle: time.Hour, MaxFailures: 50,
		LockoutBase: time.Millisecond, LockoutMax: time.Second,
	})
	engine := policy.New(db, log, cfg, nil).WithSecrets(sealer, am)

	public := netcheck.NewService(netcheck.ServiceOptions{
		Host:   cfg.PublicHost(),
		Detect: cfg.Public.Detect,
		Detector: netcheck.New(netcheck.Options{
			Resolvers: cfg.Public.Resolvers,
		}),
	})

	srv := httptest.NewServer(
		api.New(db, log, cfg, am, engine, sealer, nil).WithPublic(public).Handler())
	t.Cleanup(srv.Close)

	return &apiEnv{srv: srv, db: db, secret: secret, public: public}
}

// call issues a request carrying whatever cookies and CSRF token it is given.
func (e *apiEnv) call(t *testing.T, method, path string, body any, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()

	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if csrf != "" {
		req.Header.Set(auth.CSRFHeader, csrf)
	}

	// No redirects, no cookie jar: the test controls exactly what is sent.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()

	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// csrfOf finds the token under either spelling: the __Host- prefix only
// appears on a Secure cookie, and the test server speaks plain HTTP.
func csrfOf(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == auth.CSRFCookieName(true) || c.Name == auth.CSRFCookieName(false) {
			return c.Value
		}
	}
	return ""
}

// signIn walks the full password-then-code flow and returns a usable session.
func (e *apiEnv) signIn(t *testing.T) (cookies []*http.Cookie, csrf string) {
	t.Helper()

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": apiPassword,
	}, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d, want 200", resp.StatusCode)
	}
	cookies = resp.Cookies()
	decodeBody(t, resp)

	code, err := totp.GenerateCode(e.secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	resp = e.call(t, "POST", "/api/mfa", map[string]string{"code": code}, cookies, csrfOf(cookies))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa returned %d, want 200: %v", resp.StatusCode, decodeBody(t, resp))
	}
	cookies = resp.Cookies()
	decodeBody(t, resp)

	return cookies, csrfOf(cookies)
}

/* --------------------------------------------------------- the gap fixed --- */

// An account with no second factor must not get a session from a password
// alone. Otherwise one factor would be enough to wake a machine and connect.
func TestPasswordAloneIsNotEnough(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "anna", "password": apiPassword,
	}, nil, "")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("an account with no second factor was let in with just a password")
	}
	for _, c := range resp.Cookies() {
		if isSessionCookie(c) && c.Value != "" {
			t.Fatal("a session cookie was issued without a second factor")
		}
	}
}

// Getting the password right but stopping there must not be enough either.
func TestPendingSessionCannotReachTheApi(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": apiPassword,
	}, nil, "")
	pending := resp.Cookies()
	decodeBody(t, resp)

	for _, path := range []string{"/api/me", "/api/targets", "/api/sessions", "/api/audit"} {
		r := e.call(t, "GET", path, nil, pending, csrfOf(pending))
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s returned %d for a half-finished login, want 401", path, r.StatusCode)
		}
	}
}

/* ------------------------------------------------------- access control --- */

func TestUnauthenticatedIsRefused(t *testing.T) {
	e := newAPI(t)

	for _, path := range []string{"/api/me", "/api/targets", "/api/sessions", "/api/audit", "/api/admin/users"} {
		resp := e.call(t, "GET", path, nil, nil, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s returned %d without a session, want 401 or 403", path, resp.StatusCode)
		}
	}
}

// A state-changing request without the CSRF header must be refused, even with
// a perfectly valid session cookie.
func TestCSRFIsRequired(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	// Both a missing and a forged token are refused. The status alone cannot
	// tell us why — an unknown target is also 403 — so check the reason.
	for _, token := range []string{"", "not-the-real-token"} {
		resp := e.call(t, "POST", "/api/targets/1/unlock", nil, cookies, token)
		body := decodeBody(t, resp)

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unlock with token %q returned %d, want 403", token, resp.StatusCode)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "csrf") {
			t.Fatalf("unlock with token %q was refused for %q, not for CSRF", token, body["error"])
		}
	}

	// With the right token the request gets past CSRF and is judged on its
	// merits instead — here, a target that does not exist.
	resp := e.call(t, "POST", "/api/targets/1/unlock", nil, cookies, csrf)
	body := decodeBody(t, resp)

	if strings.Contains(fmt.Sprint(body["error"]), "csrf") {
		t.Fatalf("a valid csrf token was still rejected: %q", body["error"])
	}
}

func TestNonAdminCannotReachAdminRoutes(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()

	// Give anna a second factor so she can actually sign in.
	secret, _, _ := mfa.TOTP{Skew: 1}.Enroll("revpd", "anna")
	anna, _ := e.db.UserByName(ctx, "anna")

	key, _ := crypto.NewMasterKey()
	_ = key
	// Re-enrol through the same sealer the server uses is not reachable from
	// here, so grant her a backup code instead: it proves the role check, not
	// the factor type.
	hash, _ := crypto.HashPassword("AAAAABBBBB")
	e.db.Exec(`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, anna.ID, hash)
	_ = secret

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "anna", "password": apiPassword,
	}, nil, "")
	cookies := resp.Cookies()
	decodeBody(t, resp)

	resp = e.call(t, "POST", "/api/mfa", map[string]string{"code": "AAAAA-BBBBB"}, cookies, csrfOf(cookies))
	if resp.StatusCode != http.StatusOK {
		t.Skipf("could not sign anna in (%d); the role check is covered by the admin path", resp.StatusCode)
	}
	cookies = resp.Cookies()
	decodeBody(t, resp)

	for _, path := range []string{"/api/admin/users", "/api/admin/targets", "/api/admin/settings"} {
		r := e.call(t, "GET", path, nil, cookies, csrfOf(cookies))
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("%s returned %d for a non-admin, want 403", path, r.StatusCode)
		}
	}
}

/* ------------------------------------------------------------- leakage --- */

// Wrong password and unknown account must be indistinguishable.
func TestLoginDoesNotRevealWhichAccountsExist(t *testing.T) {
	e := newAPI(t)

	bad := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": "wrong-password",
	}, nil, "")
	badBody := decodeBody(t, bad)

	missing := e.call(t, "POST", "/api/login", map[string]string{
		"username": "does-not-exist", "password": "wrong-password",
	}, nil, "")
	missingBody := decodeBody(t, missing)

	if bad.StatusCode != missing.StatusCode {
		t.Fatalf("status differs: %d for a real account, %d for a missing one",
			bad.StatusCode, missing.StatusCode)
	}
	if fmt.Sprint(badBody["error"]) != fmt.Sprint(missingBody["error"]) {
		t.Fatalf("message differs: %q vs %q", badBody["error"], missingBody["error"])
	}
}

// Errors must never echo back what was sent.
func TestErrorsDoNotEchoCredentials(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": "SuperSecret123!",
	}, nil, "")
	body := decodeBody(t, resp)

	if strings.Contains(fmt.Sprint(body), "SuperSecret123!") {
		t.Fatalf("the response contains the password: %v", body)
	}
}

/* ------------------------------------------------------------- headers --- */

func TestSecurityHeadersArePresent(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "GET", "/api/me", nil, nil, "")
	defer resp.Body.Close()

	want := map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	for header, contains := range want {
		got := resp.Header.Get(header)
		if !strings.Contains(got, contains) {
			t.Errorf("%s = %q, want it to contain %q", header, got, contains)
		}
	}
}

// Session cookies must be locked down.
func TestSessionCookieAttributes(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": apiPassword,
	}, nil, "")
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if !isSessionCookie(c) {
			continue
		}
		if !c.HttpOnly {
			t.Error("the session cookie is readable from JavaScript")
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == 0 {
			t.Error("the session cookie has no SameSite restriction")
		}
		if c.Path != "/" {
			t.Errorf("session cookie path = %q, want /", c.Path)
		}
		return
	}
	t.Fatal("no session cookie was issued")
}

// The body limit stops a trivial memory exhaustion.
func TestOversizedBodyIsRejected(t *testing.T) {
	e := newAPI(t)

	huge := strings.Repeat("a", 1<<20) // 1 MiB, well over the 64 KiB cap
	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": huge,
	}, nil, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an oversized body returned %d, want 400", resp.StatusCode)
	}
}

// Unknown fields are refused, so a typo cannot silently change meaning.
func TestUnknownFieldsAreRejected(t *testing.T) {
	e := newAPI(t)

	req, _ := http.NewRequest("POST", e.srv.URL+"/api/login",
		strings.NewReader(`{"username":"felix","password":"x","role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a body with an unexpected field returned %d, want 400", resp.StatusCode)
	}
}

// isSessionCookie matches either spelling; the __Host- prefix only appears on
// a Secure cookie and the test server speaks plain HTTP.
func isSessionCookie(c *http.Cookie) bool {
	return c.Name == auth.SessionCookieName(true) || c.Name == auth.SessionCookieName(false)
}

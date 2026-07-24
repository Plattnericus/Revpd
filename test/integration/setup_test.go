//go:build integration

// First-run setup, and above all that the window closes for good.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/api"
	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

// newBlankAPI brings up a gateway with an empty database, as it is after a
// fresh install.
func newBlankAPI(t *testing.T) *apiEnv {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "setup.db"))
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

	key, _ := crypto.NewMasterKey()
	sealer, _ := crypto.NewSealer(key)

	am := auth.NewManager(db, auth.Options{
		TTL: time.Hour, Idle: time.Hour, MaxFailures: 50,
		LockoutBase: time.Millisecond, LockoutMax: time.Second,
	})
	engine := policy.New(db, log, cfg, nil).WithSecrets(sealer, am)

	srv := httptest.NewServer(api.New(db, log, cfg, am, engine, sealer, nil).Handler())
	t.Cleanup(srv.Close)

	return &apiEnv{srv: srv, db: db}
}

// status fetches the setup state and the CSRF token that comes with it.
func (e *apiEnv) status(t *testing.T) (needed bool, cookies []*http.Cookie, csrf string) {
	t.Helper()

	resp := e.call(t, "GET", "/api/setup/status", nil, nil, "")
	body := decodeBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup status returned %d", resp.StatusCode)
	}
	return body["setup_required"] == true, resp.Cookies(), csrfOf(resp.Cookies())
}

/* ---------------------------------------------------------- the window --- */

func TestSetupIsOfferedOnAnEmptyGateway(t *testing.T) {
	e := newBlankAPI(t)

	needed, _, _ := e.status(t)
	if !needed {
		t.Fatal("a gateway with no accounts did not offer setup")
	}
}

// The whole point: once an administrator exists the endpoint is gone.
func TestSetupClosesAfterTheFirstAdmin(t *testing.T) {
	e := newBlankAPI(t)
	_, cookies, csrf := e.status(t)

	resp := e.call(t, "POST", "/api/setup/admin", map[string]string{
		"username": "felix", "display_name": "Felix", "password": "CorrectHorseBattery",
	}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creating the first admin returned %d: %v", resp.StatusCode, decodeBody(t, resp))
	}
	decodeBody(t, resp)

	// Status must now say the wizard is done.
	if needed, _, _ := e.status(t); needed {
		t.Fatal("setup is still offered after an administrator was created")
	}

	// And a second attempt must not create anybody.
	_, cookies2, csrf2 := e.status(t)
	again := e.call(t, "POST", "/api/setup/admin", map[string]string{
		"username": "mallory", "display_name": "Mallory", "password": "AnotherLongPassword",
	}, cookies2, csrf2)
	again.Body.Close()

	if again.StatusCode == http.StatusOK {
		t.Fatal("a second administrator was created through the setup endpoint")
	}

	n, err := e.db.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("the database holds %d users, want exactly 1", len(n))
	}
	if n[0].Username != "mallory" && n[0].Username != "felix" {
		t.Fatalf("unexpected user %q", n[0].Username)
	}
	if n[0].Username == "mallory" {
		t.Fatal("the second request won — the setup window did not close")
	}
}

// Ten browsers racing to be first must produce exactly one account.
func TestConcurrentSetupCreatesOneAdmin(t *testing.T) {
	e := newBlankAPI(t)

	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			resp := e.call(t, "GET", "/api/setup/status", nil, nil, "")
			cookies := resp.Cookies()
			decodeBody(t, resp)

			r := e.call(t, "POST", "/api/setup/admin", map[string]any{
				"username":     "admin",
				"display_name": "Admin",
				"password":     "CorrectHorseBattery",
			}, cookies, csrfOf(cookies))
			r.Body.Close()

			if r.StatusCode == http.StatusOK {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("%d requests were accepted, want exactly 1", accepted)
	}

	users, _ := e.db.ListUsers(context.Background())
	if len(users) != 1 {
		t.Fatalf("the database holds %d users, want 1", len(users))
	}
}

// Setup must not be a way around CSRF.
func TestSetupRequiresCSRF(t *testing.T) {
	e := newBlankAPI(t)
	_, cookies, _ := e.status(t)

	resp := e.call(t, "POST", "/api/setup/admin", map[string]string{
		"username": "felix", "password": "CorrectHorseBattery",
	}, cookies, "")
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("setup without a csrf token returned %d, want 403", resp.StatusCode)
	}
}

// A weak password must be refused here too, not just in the CLI.
func TestSetupRejectsWeakPasswords(t *testing.T) {
	e := newBlankAPI(t)

	for _, pw := range []string{"", "short", "elevenchars"} {
		_, cookies, csrf := e.status(t)

		resp := e.call(t, "POST", "/api/setup/admin", map[string]string{
			"username": "felix", "password": pw,
		}, cookies, csrf)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Fatalf("password %q of %d characters was accepted", pw, len(pw))
		}
	}
}

/* --------------------------------------------------------- the wizard --- */

// The path a real first-run takes, start to finish.
func TestSetupWizardEndToEnd(t *testing.T) {
	e := newBlankAPI(t)
	_, cookies, csrf := e.status(t)

	// 1. Create the administrator; the response signs us in.
	resp := e.call(t, "POST", "/api/setup/admin", map[string]string{
		"username": "felix", "display_name": "Felix", "password": "CorrectHorseBattery",
	}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create admin: %d", resp.StatusCode)
	}
	decodeBody(t, resp)
	cookies = resp.Cookies()
	csrf = csrfOf(cookies)

	// 2. Enrol the authenticator.
	resp = e.call(t, "POST", "/api/setup/enroll", nil, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", resp.StatusCode)
	}
	enrolled := decodeBody(t, resp)

	secret, _ := enrolled["secret"].(string)
	if secret == "" {
		t.Fatal("enrolment returned no secret")
	}
	if uri, _ := enrolled["uri"].(string); uri == "" {
		t.Fatal("enrolment returned no otpauth uri for the QR code")
	}
	codes, _ := enrolled["backup_codes"].([]any)
	if len(codes) == 0 {
		t.Fatal("enrolment returned no backup codes")
	}

	// 3. Confirm it, so a mistyped scan is caught before it locks anyone out.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	resp = e.call(t, "POST", "/api/setup/enroll/confirm", map[string]string{"code": code}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm enrolment: %d — %v", resp.StatusCode, decodeBody(t, resp))
	}
	decodeBody(t, resp)

	// 4. Add the first machine.
	resp = e.call(t, "POST", "/api/setup/target", map[string]string{
		"name": "Office PC", "ip": "192.168.1.40", "mac": "a8:a1:59:3c:d2:11",
	}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create target: %d — %v", resp.StatusCode, decodeBody(t, resp))
	}
	decodeBody(t, resp)

	// The administrator must be able to reach it right away.
	targets := e.call(t, "GET", "/api/targets", nil, cookies, csrf)
	body := decodeBody(t, targets)
	list, _ := body["targets"].([]any)
	if len(list) != 1 {
		t.Fatalf("the new administrator sees %d machines, want 1", len(list))
	}

	// And from now on, signing in demands the second factor.
	fresh := e.call(t, "POST", "/api/login", map[string]string{
		"username": "felix", "password": "CorrectHorseBattery",
	}, nil, "")
	loginBody := decodeBody(t, fresh)

	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("login after setup returned %d", fresh.StatusCode)
	}
	if loginBody["stage"] != "mfa" {
		t.Fatalf("login stage = %v, want mfa — the second factor is not being demanded", loginBody["stage"])
	}
}

// A wrong code during enrolment must be refused, or a bad QR scan would lock
// the only administrator out of their own gateway.
func TestEnrolmentConfirmRejectsAWrongCode(t *testing.T) {
	e := newBlankAPI(t)
	_, cookies, csrf := e.status(t)

	resp := e.call(t, "POST", "/api/setup/admin", map[string]string{
		"username": "felix", "password": "CorrectHorseBattery",
	}, cookies, csrf)
	decodeBody(t, resp)
	cookies = resp.Cookies()
	csrf = csrfOf(cookies)

	resp = e.call(t, "POST", "/api/setup/enroll", nil, cookies, csrf)
	decodeBody(t, resp)

	resp = e.call(t, "POST", "/api/setup/enroll/confirm", map[string]string{"code": "000000"}, cookies, csrf)
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("a wrong code was accepted as confirmation")
	}
}

// Setup endpoints must not be reachable by a stranger once the gateway is up.
func TestSetupEndpointsAreGoneForStrangers(t *testing.T) {
	e := newAPI(t) // already has accounts

	for _, path := range []string{"/api/setup/admin", "/api/setup/enroll", "/api/setup/target"} {
		resp := e.call(t, "POST", path, map[string]string{"username": "x", "password": "y"}, nil, "")
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s answered without a session on a configured gateway", path)
		}
	}
}

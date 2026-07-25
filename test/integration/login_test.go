//go:build integration

// The RDP-native login end to end at the policy level: a real password, a real
// TOTP code, a real Wake-on-LAN, a real redirect token, and that token being
// accepted exactly once by the relay's authorisation path.
//
// The wire protocol underneath (X.224, TLS, MCS, Client Info, the redirection
// PDU) is covered separately in internal/proxy/rdp, against a client that
// walks the same sequence mstsc does.
package integration

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

type loginEnv struct {
	db     *store.DB
	log    *audit.Log
	engine *policy.Engine
	user   *store.User
	target *store.Target
	wol    *wolSink
	win    *fakeWindows

	secret   string
	password string
}

func setupLogin(t *testing.T, asleep bool, tweak func(*config.Config)) *loginEnv {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "login.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	win := newFakeWindows(t, asleep, 300*time.Millisecond)
	sink := newWolSink(t, win.wake)

	cfg := config.Defaults()
	cfg.WoL.ProbeInterval = 40 * time.Millisecond
	cfg.WoL.ProbeSettle = 0
	cfg.WoL.Repeat = 1
	cfg.Grant.TTL = time.Minute
	if tweak != nil {
		tweak(&cfg)
	}

	key, _ := crypto.NewMasterKey()
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	const password = "CorrectHorseBatteryStaple"
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	uid, err := db.CreateUser(ctx, store.User{
		Username: "felix", DisplayName: "Felix", PasswordHash: hash, Role: "user", RDPHint: "felix",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Enrol a real TOTP secret, sealed the same way the CLI does it.
	secret, _, err := mfa.TOTP{Skew: cfg.Auth.TOTPSkew}.Enroll("revpd", "felix")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	enc, err := sealer.Seal(fmt.Sprintf("totp:%d", uid), []byte(secret))
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	if err := db.SetTOTPSecret(ctx, uid, enc); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	tid, err := db.CreateTarget(ctx, store.Target{
		Name: "Büro-PC", IP: "127.0.0.1", RDPPort: win.port(),
		MAC: "a8:a1:59:3c:d2:11", WoLBroadcast: "127.0.0.1", WoLPort: sink.port(),
		BootTimeoutS: 5,
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := db.GrantTargetAccess(ctx, uid, tid); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	user, _ := db.UserByID(ctx, uid)
	target, _ := db.TargetByID(ctx, tid)

	lockout := auth.NewManager(db, auth.Options{
		TTL: time.Hour, Idle: time.Hour,
		MaxFailures: cfg.Auth.MaxFailures,
		LockoutBase: 50 * time.Millisecond,
		LockoutMax:  time.Second,
	})
	engine := policy.New(db, log, cfg, nil).WithSecrets(sealer, lockout)

	return &loginEnv{
		db: db, log: log, engine: engine, user: user, target: target,
		wol: sink, win: win, secret: secret, password: password,
	}
}

func (e *loginEnv) code(t *testing.T) string {
	t.Helper()
	c, err := totp.GenerateCode(e.secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return c
}

func (e *loginEnv) creds(password string) *rdp.Credentials {
	return &rdp.Credentials{Username: "felix", Domain: "", Password: password}
}

/* ------------------------------------------------------- the happy path --- */

// Everything the user experiences, in one test: a sleeping machine, a password
// with the code appended, Wake-on-LAN, and a token that gets them through.
func TestRDPLoginWakesAndRedirects(t *testing.T) {
	e := setupLogin(t, true, nil) // machine is powered off
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	if wolAlive(e.target) {
		t.Fatal("target answered before it was woken")
	}

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}

	// A magic packet must really have gone out for this MAC.
	if len(e.wol.packets()) == 0 {
		t.Fatal("no magic packet was sent")
	}

	// The redirection must carry a token and the credentials for Windows.
	if redir.Token == "" {
		t.Fatal("redirection carries no token")
	}
	if redir.Username != "felix" {
		t.Fatalf("redirection username = %q", redir.Username)
	}
	if redir.Password != e.password {
		t.Fatalf("redirection password = %q, want the password without the code", redir.Password)
	}
	if strings.Contains(redir.Password, ",") {
		t.Fatal("the one-time code leaked into the password handed to Windows")
	}

	// And the relay must accept exactly that token, from the same address.
	d := e.engine.AuthorizeToken(ctx, src, redir.Token)
	if !d.Allow {
		t.Fatalf("the token we just issued was refused: %s", d.Reason)
	}
	if d.Backend != e.target.Addr() {
		t.Fatalf("backend = %s, want %s", d.Backend, e.target.Addr())
	}

	if brk, _, err := e.log.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("audit chain broken after a login: %v %v", brk, err)
	}
}

// A token is good once. A replay must not get a second session.
func TestRedirectTokenIsSingleUse(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}

	if d := e.engine.AuthorizeToken(ctx, src, redir.Token); !d.Allow {
		t.Fatalf("first use refused: %s", d.Reason)
	}
	if d := e.engine.AuthorizeToken(ctx, src, redir.Token); d.Allow {
		t.Fatal("the same redirect token was accepted twice")
	}
}

// Someone who sniffs the token cannot use it from their own address.
func TestRedirectTokenIsBoundToAddress(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	redir, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}

	if d := e.engine.AuthorizeToken(ctx, net.ParseIP("198.51.100.4"), redir.Token); d.Allow {
		t.Fatal("a token issued to one address worked from another")
	}
}

func TestUnknownTokenIsRefused(t *testing.T) {
	e := setupLogin(t, false, nil)

	d := e.engine.AuthorizeToken(context.Background(), net.ParseIP("203.0.113.9"), "made-up-token")
	if d.Allow {
		t.Fatal("an invented token was accepted")
	}
}

/* --------------------------------------------------------- the refusals --- */

// Every rejection must look the same from the outside.
func TestLoginRefusals(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password func(e *loginEnv, t *testing.T) string
	}{
		{
			name:     "wrong password",
			username: "felix",
			password: func(e *loginEnv, t *testing.T) string { return "WrongPassword," + e.code(t) },
		},
		{
			name:     "unknown account",
			username: "mallory",
			password: func(e *loginEnv, t *testing.T) string { return e.password + "," + e.code(t) },
		},
		{
			name:     "wrong code",
			username: "felix",
			password: func(e *loginEnv, _ *testing.T) string { return e.password + ",000000" },
		},
		{
			// The whole point of the gateway: a bare password is not enough.
			name:     "no second factor at all",
			username: "felix",
			password: func(e *loginEnv, _ *testing.T) string { return e.password },
		},
		{
			name:     "empty factor after the comma",
			username: "felix",
			password: func(e *loginEnv, _ *testing.T) string { return e.password + "," },
		},
		{
			name:     "nothing at all",
			username: "felix",
			password: func(e *loginEnv, _ *testing.T) string { return "" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setupLogin(t, true, nil)

			redir, err := e.engine.Authenticate(context.Background(), net.ParseIP("203.0.113.9"),
				&rdp.Credentials{Username: tc.username, Password: tc.password(e, t)})

			if err == nil {
				t.Fatal("login was allowed")
			}
			if redir != nil {
				t.Fatal("a redirection was produced for a failed login")
			}
			// A refused login must not wake anything: that would leak whether
			// the account exists by listening for the magic packet.
			if len(e.wol.packets()) != 0 {
				t.Fatal("a refused login still sent a magic packet")
			}
		})
	}
}

// A code works once. The gateway must not accept it again inside its window.
func TestCodeCannotBeReplayed(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	code := e.code(t)

	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+code)); err != nil {
		t.Fatalf("first login refused: %v", err)
	}

	// Reload so the burnt counter is visible, as it would be on a real request.
	user, _ := e.db.UserByID(ctx, e.user.ID)
	if user.TOTPLastCounter == 0 {
		t.Fatal("the used step was not recorded")
	}

	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+code)); err == nil {
		t.Fatal("the same one-time code worked twice")
	}
}

// Locking the account has to bite the RDP path too, not just the portal.
func TestLockedAccountCannotLogIn(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	if err := e.db.SetUserStatus(ctx, e.user.ID, "locked"); err != nil {
		t.Fatalf("lock: %v", err)
	}

	if _, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+e.code(t))); err == nil {
		t.Fatal("a locked account logged in")
	}
}

// Repeated failures must eventually stop being answered at all.
func TestBruteForceGetsLockedOut(t *testing.T) {
	e := setupLogin(t, false, func(c *config.Config) { c.Auth.MaxFailures = 3 })
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	for i := 0; i < 5; i++ {
		e.engine.Authenticate(ctx, src, e.creds("WrongPassword,000000"))
	}

	// Even the correct credentials are refused while the lockout holds.
	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t))); err == nil {
		t.Fatal("brute forcing was not throttled")
	}
}

// A backup code is accepted once and then spent.
func TestBackupCodeWorksOnce(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	code, err := crypto.NewBackupCode()
	if err != nil {
		t.Fatalf("new backup code: %v", err)
	}
	hash, err := crypto.HashPassword(crypto.NormalizeBackupCode(code))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := e.db.Exec(`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, e.user.ID, hash); err != nil {
		t.Fatalf("store backup code: %v", err)
	}

	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+code)); err != nil {
		t.Fatalf("backup code refused: %v", err)
	}
	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+code)); err == nil {
		t.Fatal("the same backup code worked twice")
	}
}

// A password containing commas must survive the split intact.
func TestPasswordWithCommasStillWorks(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	const tricky = "Hello,World,With,Commas"
	hash, err := crypto.HashPassword(tricky)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := e.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, e.user.ID); err != nil {
		t.Fatalf("update password: %v", err)
	}

	redir, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(tricky+","+e.code(t)))
	if err != nil {
		t.Fatalf("login with a comma-laden password refused: %v", err)
	}
	if redir.Password != tricky {
		t.Fatalf("password handed to Windows = %q, want %q", redir.Password, tricky)
	}
}

// mstsc often sends DOMAIN\user or user@domain. Both must resolve.
func TestDomainQualifiedUsernames(t *testing.T) {
	for _, name := range []string{"felix", "CORP\\felix", "felix@corp.local"} {
		t.Run(name, func(t *testing.T) {
			e := setupLogin(t, false, nil)

			_, err := e.engine.Authenticate(context.Background(), net.ParseIP("203.0.113.9"),
				&rdp.Credentials{Username: name, Password: e.password + "," + e.code(t)})
			if err != nil {
				t.Fatalf("login as %q refused: %v", name, err)
			}
		})
	}
}

// Nothing about the password may reach the audit trail.
func TestPasswordNeverReachesTheAuditLog(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	code := e.code(t)
	e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+code))
	e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds("SomeWrongPassword,111111"))

	entries, err := e.log.List(ctx, audit.Query{Limit: 500})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}

	for _, entry := range entries {
		blob := fmt.Sprint(entry.Detail) + entry.Object + entry.Actor
		for _, secret := range []string{e.password, code, "SomeWrongPassword"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("audit entry %d (%s) contains a secret: %s", entry.ID, entry.Action, blob)
			}
		}
	}
}

// Two logins at once must not both burn the same TOTP step or fork the audit chain.
func TestConcurrentLoginsAreSafe(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	code := e.code(t)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+code)); err == nil {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed == 0 {
		t.Fatal("no login succeeded at all")
	}
	if brk, _, err := e.log.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("concurrent logins broke the audit chain: %v %v", brk, err)
	}
}

func wolAlive(t *store.Target) bool {
	c, err := net.DialTimeout("tcp", t.Addr(), 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

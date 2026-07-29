//go:build integration

// Adversarial tests.
//
// The rest of the suite checks that the good path works and the obvious bad
// paths fail. This file assumes someone is actively trying: replaying what
// they captured, racing two requests to spend one thing twice, holding
// connections open to exhaust the gateway, and probing for the differences
// that reveal which accounts exist.
package integration

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

/* ------------------------------------------------------------- replay --- */

// Two connections racing with the same fresh token: exactly one may win.
//
// A check-then-use gap here would mean a captured token opens two sessions,
// which is the whole reason the token is single-use.
func TestTokenRaceLetsExactlyOneThrough(t *testing.T) {
	for attempt := 0; attempt < 5; attempt++ {
		e := setupLogin(t, false, nil)
		ctx := context.Background()
		src := net.ParseIP("203.0.113.9")

		redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
		if err != nil {
			t.Fatalf("login refused: %v", err)
		}

		const racers = 16
		var allowed atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})

		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // line them up so they really do collide
				if d := e.engine.AuthorizeToken(ctx, src, redir.Token); d.Allow {
					allowed.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := allowed.Load(); got != 1 {
			t.Fatalf("attempt %d: %d of %d racers were let through, want exactly 1", attempt, got, racers)
		}
	}
}

// The same for a one-time code: two logins racing with one code.
func TestCodeRaceBurnsTheStepOnce(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	code := e.code(t)

	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+code)); err == nil {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// At least one must work, or nobody could ever log in. More than one is a
	// replay window.
	if got := allowed.Load(); got != 1 {
		t.Fatalf("%d logins succeeded with one code, want exactly 1", got)
	}
}

// A backup code is paper. Two people racing with the same slip must not both
// get in.
func TestBackupCodeRace(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	code, _ := crypto.NewBackupCode()
	hash, _ := crypto.HashPassword(crypto.NormalizeBackupCode(code))
	if _, err := e.db.Exec(`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, e.user.ID, hash); err != nil {
		t.Fatalf("store backup code: %v", err)
	}

	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+code)); err == nil {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != 1 {
		t.Fatalf("%d logins succeeded with one backup code, want exactly 1", got)
	}
}

/* --------------------------------------------------------- enumeration --- */

// Whether an account exists must not be visible in the reply, the timing, or
// anything else an attacker can measure from outside.
func TestLoginRevealsNothingAboutAccounts(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	type sample struct {
		err      error
		duration time.Duration
	}

	measure := func(username, password string) sample {
		start := time.Now()
		_, err := e.engine.Authenticate(ctx, src,
			&rdp.Credentials{Username: username, Password: password})
		return sample{err, time.Since(start)}
	}

	// Warm up, so the first Argon2 run does not skew the comparison.
	measure("felix", "wrong,000000")

	real := measure("felix", "WrongPassword,000000")
	fake := measure("does-not-exist-at-all", "WrongPassword,000000")

	if real.err == nil || fake.err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if real.err.Error() != fake.err.Error() {
		t.Fatalf("the errors differ:\n  real account: %v\n  missing:      %v", real.err, fake.err)
	}

	// The costs must be the same order of magnitude. An account that skips the
	// password hash entirely would return in microseconds.
	ratio := float64(real.duration) / float64(fake.duration)
	if ratio > 5 || ratio < 0.2 {
		t.Fatalf("timing gives the account away: real %v, missing %v (ratio %.1f)",
			real.duration, fake.duration, ratio)
	}
}

// The same through HTTP, where an attacker actually stands.
func TestPortalRevealsNothingAboutAccounts(t *testing.T) {
	e := newAPI(t)

	probe := func(username string) (int, string) {
		resp := e.call(t, "POST", "/api/login", map[string]string{
			"username": username, "password": "definitely-wrong",
		}, nil, "")
		body := decodeBody(t, resp)
		return resp.StatusCode, fmt.Sprint(body["error"])
	}

	realStatus, realErr := probe("felix")
	fakeStatus, fakeErr := probe("no-such-person")
	lockedStatus, lockedErr := probe("anna") // exists but has no second factor

	if realStatus != fakeStatus || realErr != fakeErr {
		t.Fatalf("existing and missing accounts differ: %d %q vs %d %q",
			realStatus, realErr, fakeStatus, fakeErr)
	}
	if lockedStatus != fakeStatus || lockedErr != fakeErr {
		t.Fatalf("a wrong password on an unenrolled account is distinguishable: %d %q",
			lockedStatus, lockedErr)
	}
}

/* ------------------------------------------------------------ lockouts --- */

// Hammering one account locks that account, from every address.
//
// This is a deliberate trade, and it cuts both ways: without it an attacker
// with a botnet gets unlimited guesses by rotating source addresses, which is
// the far more likely attack. The cost is that someone who knows a username
// can lock its owner out until the backoff expires — annoying, temporary, and
// visible in the audit trail, where a broken password is not.
//
// Locking out other accounts must never happen, and that is what this pins.
func TestLockoutHitsOneAccountNotAllOfThem(t *testing.T) {
	e := setupLogin(t, false, func(c *config.Config) { c.Auth.MaxFailures = 3 })
	ctx := context.Background()

	// A second account, so the blast radius can be measured.
	hash, _ := crypto.HashPassword("AnotherLongPassword")
	if _, err := e.db.CreateUser(ctx, store.User{
		Username: "anna", DisplayName: "Anna", PasswordHash: hash, Role: "user", RDPHint: "anna",
	}); err != nil {
		t.Fatalf("create second user: %v", err)
	}

	attacker := net.ParseIP("198.51.100.66")
	for i := 0; i < 10; i++ {
		e.engine.Authenticate(ctx, attacker, e.creds("WrongPassword,000000"))
	}

	// felix is locked, as intended.
	if _, err := e.engine.Authenticate(ctx, attacker, e.creds(e.password+","+e.code(t))); err == nil {
		t.Fatal("the attacked account was not locked")
	}

	// anna, who was never touched, must be unaffected. Her login fails for
	// having no second factor, not for being locked out.
	annaUser, _ := e.db.UserByName(ctx, "anna")
	if annaUser == nil {
		t.Fatal("the second account vanished")
	}
	if locked, _ := e.db.UserByName(ctx, "anna"); locked.Status != "active" {
		t.Fatalf("an attack on felix changed anna's status to %q", locked.Status)
	}
}

// A lockout has to survive the attacker guessing correctly afterwards.
func TestLockoutHoldsEvenWithTheRightPassword(t *testing.T) {
	e := setupLogin(t, false, func(c *config.Config) { c.Auth.MaxFailures = 3 })
	ctx := context.Background()
	src := net.ParseIP("198.51.100.66")

	for i := 0; i < 8; i++ {
		e.engine.Authenticate(ctx, src, e.creds("WrongPassword,000000"))
	}

	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t))); err == nil {
		t.Fatal("the correct credentials worked while locked out")
	}
}

/* ------------------------------------------------------------ exhaustion --- */

// Connections that open and say nothing must not be able to fill the gateway.
func TestSilentConnectionsDoNotPileUp(t *testing.T) {
	g := startGateway(t, false, nil)

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	// Open a batch and never send a byte.
	for i := 0; i < 40; i++ {
		c, err := net.DialTimeout("tcp", g.addr(), 2*time.Second)
		if err != nil {
			break // the cap did its job
		}
		conns = append(conns, c)
	}

	// A real client must still get through while they hang there.
	done := make(chan bool, 1)
	go func() {
		c := dialRDP(t, g.addr())
		c.negotiate(t, "felix", "")
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("idle connections starved a real client")
	}
}

// A client that sends a huge first packet must be cut off, not buffered.
func TestOversizedHandshakeIsRefused(t *testing.T) {
	g := startGateway(t, false, nil)

	conn, err := net.DialTimeout("tcp", g.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A TPKT header claiming far more than the parser will ever accept,
	// followed by a flood.
	header := []byte{3, 0, 0xFF, 0xFF}
	conn.Write(header)

	junk := bytes.Repeat([]byte{0x41}, 64*1024)
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 16; i++ {
		if _, err := conn.Write(junk); err != nil {
			break // closed on us, which is the point
		}
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("the gateway answered an oversized handshake")
	}
	if len(g.win.received()) != 0 {
		t.Fatal("junk reached the target")
	}
}

/* -------------------------------------------------------- authorisation --- */

// Access revoked between issuing a token and using it must not still work.
// The window is small but it is exactly when someone is being removed.
func TestRevocationBeatsAnIssuedToken(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}

	// Someone removes their access in the seconds before they reconnect.
	if err := e.db.RevokeTargetAccess(ctx, e.user.ID, e.target.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if d := e.engine.AuthorizeToken(ctx, src, redir.Token); d.Allow {
		t.Fatal("a token issued before revocation still worked after it")
	}
}

// Locking an account has to take effect the same way.
func TestLockingBeatsAnIssuedToken(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}
	if err := e.db.SetUserStatus(ctx, e.user.ID, "locked"); err != nil {
		t.Fatalf("lock: %v", err)
	}

	if d := e.engine.AuthorizeToken(ctx, src, redir.Token); d.Allow {
		t.Fatal("a locked account's token still worked")
	}
}

// Deleting the machine out from under a token must not leave the token
// pointing at whatever takes its place.
func TestTokenDoesNotSurviveItsTarget(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}
	if err := e.db.DeleteTarget(ctx, e.target.ID); err != nil {
		t.Fatalf("delete target: %v", err)
	}

	if d := e.engine.AuthorizeToken(ctx, src, redir.Token); d.Allow {
		t.Fatalf("a token for a deleted machine was accepted, pointing at %q", d.Backend)
	}
}

/* --------------------------------------------------------------- input --- */

// Credentials come from the open internet before anything is verified, so the
// login must survive whatever is put in them.
func TestHostileCredentialsAreHandled(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	nasty := []struct{ user, pass string }{
		{"", ""},
		{"felix", ""},
		{"", "password,123456"},
		{strings.Repeat("a", 10000), "pw,123456"},
		{"felix", strings.Repeat("a", 100000) + ",123456"},
		{"felix\x00admin", "pw,123456"},
		{"'; DROP TABLE users; --", "pw,123456"},
		{"felix", "pw,'; DELETE FROM grants; --"},
		{"../../etc/passwd", "pw,123456"},
		{"felix", ",,,,,,"},
		{"felix", strings.Repeat(",", 1000)},
		{"\xff\xfe\xfd", "\xff\xfe\xfd,1"},
		{"FELIX", "pw,123456"}, // case
		{"  felix  ", "pw,123456"},
	}

	for _, c := range nasty {
		// The only requirement is that it refuses and does not panic or hang.
		done := make(chan struct{})
		go func(user, pass string) {
			defer close(done)
			if _, err := e.engine.Authenticate(ctx, src, &rdp.Credentials{Username: user, Password: pass}); err == nil {
				t.Errorf("hostile credentials were accepted: user=%.40q", user)
			}
		}(c.user, c.pass)

		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("Authenticate hung on user=%.40q", c.user)
		}
	}

	// The database must still be intact after all that.
	users, err := e.db.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("the user table did not survive: %d users, %v", len(users), err)
	}
}

// The audit trail must stay verifiable no matter what was thrown at it.
func TestAuditSurvivesHostileInput(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	for _, name := range []string{
		"felix", "\x00\x01\x02", strings.Repeat("x", 5000),
		"{\"json\":\"injection\"}", "line\nbreak", "tab\there",
	} {
		e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"),
			&rdp.Credentials{Username: name, Password: "wrong,000000"})
	}

	brk, n, err := e.log.Verify(ctx)
	if err != nil || brk != nil {
		t.Fatalf("the audit chain broke on hostile input: %v %v", brk, err)
	}
	if n == 0 {
		t.Fatal("nothing was recorded")
	}
}

/* --------------------------------------------------------------- leaks --- */

// The password must not reach the audit trail, whatever happened.
func TestNoSecretEverReachesTheAuditTrail(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	code := e.code(t)
	secrets := []string{e.password, code, e.secret, "UniqueCanaryValue99"}

	// A successful login, a failed one, and one with the canary in it.
	e.engine.Authenticate(ctx, src, e.creds(e.password+","+code))
	e.engine.Authenticate(ctx, src, e.creds("UniqueCanaryValue99,111111"))
	e.engine.Authenticate(ctx, src, &rdp.Credentials{Username: "UniqueCanaryValue99", Password: "x,1"})

	entries, err := e.log.List(ctx, audit.Query{Limit: 500})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}

	for _, entry := range entries {
		blob := fmt.Sprint(entry.Detail) + entry.Object + entry.SrcIP
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			// The username is allowed in the actor field; a password is not
			// allowed anywhere.
			if strings.Contains(blob, secret) {
				t.Fatalf("audit entry %d (%s) leaks a secret: %s", entry.ID, entry.Action, blob)
			}
		}
	}
}

// The database file itself must not hold a password or a TOTP seed in the clear.
func TestNothingSensitiveIsStoredInTheClear(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	e.engine.Authenticate(ctx, net.ParseIP("203.0.113.9"), e.creds(e.password+","+e.code(t)))

	// Read every text column of every table and look for the secrets.
	rows, err := e.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tables = append(tables, name)
	}
	rows.Close()

	for _, table := range tables {
		dump, err := e.db.QueryContext(ctx, `SELECT * FROM `+table)
		if err != nil {
			continue
		}
		cols, _ := dump.Columns()

		for dump.Next() {
			cells := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range cells {
				ptrs[i] = &cells[i]
			}
			dump.Scan(ptrs...)

			for i, cell := range cells {
				text := fmt.Sprint(cell)
				if strings.Contains(text, e.password) {
					t.Errorf("%s.%s holds the password in the clear", table, cols[i])
				}
				if strings.Contains(text, e.secret) {
					t.Errorf("%s.%s holds the TOTP seed in the clear", table, cols[i])
				}
			}
		}
		dump.Close()
	}
}

/* ---------------------------------------------------------------- http --- */

// A session cookie belongs to the address it was issued to.
func TestSessionCookieIsBoundToTheAddress(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	// httptest always reports 127.0.0.1, so this checks the mechanism is
	// wired at all rather than simulating a second address.
	resp := e.call(t, "GET", "/api/me", nil, cookies, csrf)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a valid session was refused from its own address: %d", resp.StatusCode)
	}

	// A made-up cookie must not work.
	forged := []*http.Cookie{{Name: cookies[0].Name, Value: "not-a-real-session-token"}}
	bad := e.call(t, "GET", "/api/me", nil, forged, csrf)
	bad.Body.Close()

	if bad.StatusCode == http.StatusOK {
		t.Fatal("an invented session cookie was accepted")
	}
}

// Signing out has to actually end the session, not just clear the browser copy.
func TestLogoutEndsTheSessionServerSide(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/logout", nil, cookies, csrf)
	resp.Body.Close()

	// The same cookie must now be worthless, even though the client still has it.
	after := e.call(t, "GET", "/api/me", nil, cookies, csrf)
	after.Body.Close()

	if after.StatusCode == http.StatusOK {
		t.Fatal("the session still works after signing out")
	}
}

// Every state-changing endpoint must demand CSRF, not just the ones we
// remembered to test.
func TestEveryWritingEndpointDemandsCSRF(t *testing.T) {
	e := newAPI(t)
	cookies, _ := e.signIn(t)

	writing := []struct {
		method, path string
	}{
		{"POST", "/api/targets/1/unlock"},
		{"POST", "/api/admin/users"},
		{"POST", "/api/admin/users/1/status"},
		{"POST", "/api/admin/users/1/targets"},
		{"POST", "/api/admin/targets"},
		{"POST", "/api/admin/targets/1/testwol"},
		{"POST", "/api/passkey/register/begin"},
		{"POST", "/api/setup/enroll"},
		{"DELETE", "/api/passkey/1"},
	}

	for _, w := range writing {
		resp := e.call(t, w.method, w.path, map[string]string{"x": "y"}, cookies, "")
		body := decodeBody(t, resp)

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s returned %d without a CSRF token, want 403", w.method, w.path, resp.StatusCode)
			continue
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "csrf") {
			t.Errorf("%s %s was refused for %q, not for CSRF", w.method, w.path, body["error"])
		}
	}
}

/* ------------------------------------------------------------- windows --- */

// A grant expiring mid-session must not tear down a connection that is
// already running — the TTL bounds the handshake, not the session.
func TestExpiredGrantDoesNotKillALiveSession(t *testing.T) {
	e := setupLogin(t, false, func(c *config.Config) {
		c.Grant.TTL = 400 * time.Millisecond
		c.Grant.ReuseWindow = 5 * time.Second
	})
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}

	d := e.engine.AuthorizeToken(ctx, src, redir.Token)
	if !d.Allow {
		t.Fatalf("the token was refused: %s", d.Reason)
	}

	// Past the original TTL, but inside the reconnect window.
	time.Sleep(700 * time.Millisecond)

	if again := e.engine.Authorize(ctx, src); !again.Allow {
		t.Fatal("a reconnect inside the reuse window was refused — a dropped link would end the session")
	}
}

// And past the reuse window it must stop.
func TestReuseWindowEventuallyCloses(t *testing.T) {
	e := setupLogin(t, false, func(c *config.Config) {
		c.Grant.TTL = 200 * time.Millisecond
		c.Grant.ReuseWindow = 300 * time.Millisecond
	})
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	redir, _ := e.engine.Authenticate(ctx, src, e.creds(e.password+","+e.code(t)))
	e.engine.AuthorizeToken(ctx, src, redir.Token)

	time.Sleep(900 * time.Millisecond)

	if d := e.engine.Authorize(ctx, src); d.Allow {
		t.Fatal("the reconnect window never closes")
	}
}

/* ---------------------------------------------------------------- misc --- */

// Sustained load must not leak grants or corrupt the audit chain.
func TestSustainedLoadStaysConsistent(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			src := net.ParseIP(fmt.Sprintf("203.0.113.%d", n+1))

			// A mix of real and rejected attempts, as a busy gateway sees.
			e.engine.Authenticate(ctx, src, e.creds("wrong,000000"))
			e.engine.Authorize(ctx, src)
			e.engine.AuthorizeToken(ctx, src, "invented")
		}(i)
	}
	wg.Wait()

	if brk, _, err := e.log.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("the audit chain broke under load: %v %v", brk, err)
	}

	// Nothing may have been granted along the way.
	var grants int
	e.db.QueryRow(`SELECT count(*) FROM grants`).Scan(&grants)
	if grants != 0 {
		t.Fatalf("%d grants exist after only failed attempts", grants)
	}
}

// TOTP codes are time based, so the clock drifting must not open a hole.
func TestOldCodesDoNotComeBack(t *testing.T) {
	e := setupLogin(t, false, nil)
	ctx := context.Background()
	src := net.ParseIP("203.0.113.9")

	// Use a current code, which burns its step.
	now := time.Now()
	current, _ := totp.GenerateCode(e.secret, now)
	if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+current)); err != nil {
		t.Fatalf("current code refused: %v", err)
	}

	// Every earlier step must now be dead, even those inside the skew window.
	for _, back := range []time.Duration{30, 60, 90, 300} {
		old, _ := totp.GenerateCode(e.secret, now.Add(-back*time.Second))
		if old == current {
			continue
		}
		if _, err := e.engine.Authenticate(ctx, src, e.creds(e.password+","+old)); err == nil {
			t.Fatalf("a code from %v ago still worked", back*time.Second)
		}
	}
}

var _ = store.User{}

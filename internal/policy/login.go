package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/store"
)

// errLoginRefused is the only error the RDP login ever reports outward.
//
// Wrong password, unknown account, bad code, no access to the target: they all
// come back as this. Anything more specific turns the login into an oracle.
var errLoginRefused = errors.New("login refused")

// redirectTTL is how long the client has to come back with its token. The
// reconnect is immediate, so this only has to cover the round trip.
const redirectTTL = 60 * time.Second

// Authenticate implements rdp.Authenticator: it is the whole policy for the
// RDP-native login.
//
// creds.Password still carries the MFA suffix. It is split here, checked, and
// never stored, logged or put in the audit trail.
func (e *Engine) Authenticate(ctx context.Context, srcIP net.IP, creds *rdp.Credentials) (*rdp.Redirection, error) {
	password, factor := rdp.SplitPassword(creds.Password)

	// Strip a domain prefix: people type DOMAIN\name or name@domain out of habit.
	name := bareUsername(creds.Username)

	ipKey := e.key(srcIP)
	logDenied := func(reason string) {
		e.audit(ctx, audit.Entry{
			Actor: name, Action: audit.ActionLoginFail, SrcIP: srcIP.String(),
			Detail: map[string]any{"via": "rdp", "reason": reason},
		})
	}

	if locked, _ := e.locked(ipKey, name); locked {
		logDenied("locked out")
		return nil, errLoginRefused
	}

	user, err := e.db.UserByName(ctx, name)
	if err != nil {
		// Spend the same work as a real check so the timing does not reveal
		// whether the account exists.
		crypto.SpendVerifyTime(password)
		e.fail(ipKey, name)
		logDenied("unknown account")
		return nil, errLoginRefused
	}
	if !user.IsActive() {
		crypto.SpendVerifyTime(password)
		e.fail(ipKey, name)
		logDenied("account not active")
		return nil, errLoginRefused
	}

	if err := crypto.VerifyPassword(password, user.PasswordHash); err != nil {
		e.fail(ipKey, name)
		logDenied("wrong password")
		return nil, errLoginRefused
	}

	// No comma means no second factor was supplied.
	//
	// Normally that is the end of it: a gateway that lets a password through on
	// its own is a plain port forward with extra steps. It is allowed only
	// where the requirement has been turned off deliberately *and* the account
	// has nothing enrolled — an account that does have a second factor must
	// always use it, whatever the setting says, or turning the requirement off
	// would silently weaken every existing account.
	withFactor := factor != ""

	switch {
	case !withFactor:
		// Allowed only where the requirement has been turned off *and* this
		// account has enrolled nothing. An account that does have a second
		// factor must always use it, whatever the setting says — otherwise
		// turning the requirement off would silently weaken every account that
		// already had one.
		if e.cfg.Auth.RequireSecondFactor || len(user.TOTPSecretEnc) > 0 {
			e.fail(ipKey, name)
			logDenied("no second factor supplied")
			return nil, errLoginRefused
		}

	case !e.checkSecondFactor(ctx, user, factor, srcIP):
		e.fail(ipKey, name)
		e.audit(ctx, audit.Entry{
			Actor: user.Username, Action: audit.ActionMFAFail, SrcIP: srcIP.String(),
			Detail: map[string]any{"via": "rdp"},
		})
		return nil, errLoginRefused
	}

	e.succeed(ipKey, name)

	// Recorded differently, because an audit trail that cannot tell one factor
	// from two is not much of a trail.
	if withFactor {
		e.audit(ctx, audit.Entry{
			Actor: user.Username, Action: audit.ActionMFAOK, SrcIP: srcIP.String(),
			Detail: map[string]any{"via": "rdp"},
		})
	} else {
		e.audit(ctx, audit.Entry{
			Actor: user.Username, Action: audit.ActionLoginOK, SrcIP: srcIP.String(),
			Detail: map[string]any{"via": "rdp", "second_factor": false},
		})
	}

	target, err := e.targetFor(ctx, user)
	if err != nil {
		logDenied("no target available")
		return nil, errLoginRefused
	}

	// Wake it and wait. The client is holding on, so this has to finish inside
	// the login's overall timeout.
	e.wake(ctx, target)

	boot, cancel := context.WithTimeout(ctx, time.Duration(target.BootTimeoutS)*time.Second)
	defer cancel()
	if err := e.waitReady(boot, target); err != nil {
		e.audit(ctx, audit.Entry{
			Actor: user.Username, Action: audit.ActionTargetTimeout, Object: target.Name,
			SrcIP: srcIP.String(),
		})
		return nil, fmt.Errorf("target did not come up: %w", err)
	}

	token, err := crypto.RandomToken(24)
	if err != nil {
		return nil, err
	}
	if err := e.db.CreateRedirectToken(ctx, crypto.HashToken(token), user.ID, target.ID, ipKey, redirectTTL); err != nil {
		return nil, err
	}

	e.audit(ctx, audit.Entry{
		Actor: user.Username, Action: audit.ActionGrantIssued, Object: target.Name,
		SrcIP: srcIP.String(), Detail: map[string]any{"via": "rdp-redirect"},
	})

	return &rdp.Redirection{
		Token: token,

		// Handed straight back to Windows so the user types once. Never stored.
		Username: creds.Username,
		Domain:   creds.Domain,
		Password: password,
	}, nil
}

// AuthorizeToken resolves the routing token of a redirected reconnect.
func (e *Engine) AuthorizeToken(ctx context.Context, srcIP net.IP, token string) relay.Decision {
	rt, err := e.db.ConsumeRedirectToken(ctx, crypto.HashToken(token), e.key(srcIP))
	if err != nil {
		// Expired, already used, or issued to a different address.
		return relay.Decision{Reason: "redirect token is not valid"}
	}

	target, err := e.db.TargetByID(ctx, rt.TargetID)
	if err != nil {
		return relay.Decision{Reason: "target no longer exists"}
	}

	user, err := e.db.UserByID(ctx, rt.UserID)
	if err != nil || !user.IsActive() {
		return relay.Decision{Reason: "account is no longer active"}
	}
	if ok, err := e.db.CanReach(ctx, user, target.ID); err != nil || !ok {
		return relay.Decision{Reason: "account may no longer reach this target"}
	}

	// Issue a normal grant too, so a reconnect after a dropped link works
	// without another trip through the login.
	//
	// It lasts for the reuse window rather than the grant TTL: the TTL bounds
	// how long someone has to *start* connecting, while this covers a session
	// already under way. Using the TTL here would end a live session the
	// moment the network hiccupped after it expired.
	grantID, err := e.issueFor(ctx, user, target, e.key(srcIP), "portal", e.cfg.Grant.ReuseWindow)
	if err != nil {
		slog.Warn("could not issue a follow-on grant", "err", err)
	}

	return relay.Decision{
		Allow:    true,
		Backend:  target.Addr(),
		GrantID:  grantID,
		TargetID: target.ID,
	}
}

// checkSecondFactor accepts a TOTP code, a backup code, or a push approval.
func (e *Engine) checkSecondFactor(ctx context.Context, u *store.User, factor string, srcIP net.IP) bool {
	// "push" asks the phone instead of carrying a code.
	if strings.EqualFold(factor, "push") {
		if e.sender == nil {
			return false
		}
		ok, err := e.sender.Approve(ctx, u.Username, srcIP.String(), "")
		return err == nil && ok
	}

	// Backup codes are ten characters from a restricted alphabet.
	if norm := crypto.NormalizeBackupCode(factor); len(norm) == 10 && !isAllDigits(norm) {
		return e.consumeBackupCode(ctx, u, norm)
	}

	if len(u.TOTPSecretEnc) == 0 || e.sealer == nil {
		return false
	}
	secret, err := e.sealer.Open(fmt.Sprintf("totp:%d", u.ID), u.TOTPSecretEnc)
	if err != nil {
		slog.Error("could not decrypt totp secret", "user", u.Username, "err", err)
		return false
	}

	counter, err := mfa.TOTP{Skew: e.cfg.Auth.TOTPSkew}.Verify(string(secret), factor, u.TOTPLastCounter, time.Now())
	if err != nil {
		return false
	}

	// Claim the step, and only accept the login if this call is what burned
	// it. Two logins arriving together with the same code both pass Verify —
	// they read the same counter — so the database has to pick one.
	if err := e.db.ClaimTOTPCounter(ctx, u.ID, counter); err != nil {
		if !errors.Is(err, store.ErrCounterAlreadyUsed) {
			slog.Error("could not record totp counter", "user", u.Username, "err", err)
		}
		return false
	}
	return true
}

func (e *Engine) consumeBackupCode(ctx context.Context, u *store.User, norm string) bool {
	// Read the candidates and close the cursor before writing anything. The
	// pool is capped at one connection, so an UPDATE issued while this query
	// is still open would wait for a connection the query itself is holding.
	codes, err := e.db.OpenBackupCodes(ctx, u.ID)
	if err != nil {
		return false
	}

	for _, c := range codes {
		if crypto.VerifyPassword(norm, c.Hash) != nil {
			continue
		}
		// Claim it in the same statement that checks it, so two logins racing
		// with the same code cannot both spend it.
		return e.db.ClaimBackupCode(ctx, c.ID) == nil
	}
	return false
}

// targetFor picks the machine this account should reach.
func (e *Engine) targetFor(ctx context.Context, u *store.User) (*store.Target, error) {
	targets, err := e.db.ListTargetsForUser(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets available")
	}
	if len(targets) == 1 {
		return &targets[0], nil
	}

	if name := e.cfg.JIT.DefaultTarget; name != "" {
		for i := range targets {
			if targets[i].Name == name {
				return &targets[i], nil
			}
		}
	}
	// With several machines and no default there is nothing sensible to pick.
	// The portal exists for exactly this case.
	return nil, errors.New("account has several targets and none is the default")
}

func bareUsername(s string) string {
	if i := strings.LastIndex(s, "\\"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

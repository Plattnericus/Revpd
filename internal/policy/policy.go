// Package policy decides who may reach which target, and wakes it on the way.
//
// It implements relay.Policy. Everything the relay is allowed to forward comes
// through here, so this file is the enforcement point for the invariant in
// CLAUDE.md section 6.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/proxy/x224"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/wol"
)

// Approver asks a human to confirm an out-of-band connection attempt.
// Duo implements this; a mock stands in for tests.
type Approver interface {
	Approve(ctx context.Context, username, srcIP, target string) (bool, error)
}

type Engine struct {
	db  *store.DB
	log *audit.Log
	cfg config.Config

	// sealer decrypts TOTP secrets. Nil only in tests that never touch MFA.
	sealer *crypto.Sealer

	// lockout is shared with the web portal, so failures on either path count
	// towards the same limit.
	lockout *auth.Manager

	sender Approver
	waker  wol.Sender
	prober wol.Prober

	// One wake per target at a time. Ten browser tabs must not mean ten
	// magic packets and ten prober goroutines.
	wakeMu sync.Mutex
	waking map[int64]*wakeState
}

type wakeState struct {
	started time.Time
	done    chan struct{}
	err     error
}

func New(db *store.DB, log *audit.Log, cfg config.Config, approver Approver) *Engine {
	return &Engine{
		db:     db,
		log:    log,
		cfg:    cfg,
		sender: approver,
		waker:  wol.Sender{Repeat: cfg.WoL.Repeat},
		prober: wol.Prober{Interval: cfg.WoL.ProbeInterval, Settle: cfg.WoL.ProbeSettle},
		waking: map[int64]*wakeState{},
	}
}

// WithSecrets supplies what the RDP-native login needs: the key that unseals
// TOTP secrets and the shared lockout counter.
func (e *Engine) WithSecrets(sealer *crypto.Sealer, lockout *auth.Manager) *Engine {
	e.sealer = sealer
	e.lockout = lockout
	return e
}

// The lockout helpers tolerate a nil manager so tests can skip it.
func (e *Engine) locked(ipKey, user string) (bool, time.Duration) {
	if e.lockout == nil {
		return false, 0
	}
	if yes, d := e.lockout.Locked("ip:" + ipKey); yes {
		return true, d
	}
	return e.lockout.Locked("user:" + user)
}

func (e *Engine) fail(ipKey, user string) {
	if e.lockout == nil {
		return
	}
	e.lockout.Fail("ip:" + ipKey)
	e.lockout.Fail("user:" + user)
}

func (e *Engine) succeed(ipKey, user string) {
	if e.lockout == nil {
		return
	}
	e.lockout.Succeed("ip:" + ipKey)
	e.lockout.Succeed("user:" + user)
}

func (e *Engine) key(ip net.IP) string {
	return store.NormalizeIP(ip, e.cfg.Grant.IPv4PrefixBits, e.cfg.Grant.IPv6PrefixBits)
}

/* ------------------------------------------------------ relay.Policy --- */

// Authorize is the portal path. It reads no packet data at all: either this
// address already passed MFA, or it does not get through.
func (e *Engine) Authorize(ctx context.Context, srcIP net.IP) relay.Decision {
	now := time.Now()

	g, err := e.db.ActiveGrant(ctx, e.key(srcIP), now)
	if errors.Is(err, store.ErrNotFound) {
		return relay.Decision{Reason: "no valid grant for this address"}
	}
	if err != nil {
		slog.Error("grant lookup failed", "src", srcIP, "err", err)
		// Fail closed. A database hiccup must never open the door.
		return relay.Decision{Reason: "grant lookup failed"}
	}

	target, err := e.db.TargetByID(ctx, g.TargetID)
	if err != nil {
		return relay.Decision{Reason: "target no longer exists"}
	}

	// Re-check access at connect time: an admin may have revoked it since.
	user, err := e.db.UserByID(ctx, g.UserID)
	if err != nil || !user.IsActive() {
		return relay.Decision{Reason: "account is no longer active"}
	}
	ok, err := e.db.CanReach(ctx, user, target.ID)
	if err != nil || !ok {
		return relay.Decision{Reason: "account may no longer reach this target"}
	}

	// Extend so a reconnect after a dropped link does not demand fresh MFA.
	if err := e.db.ConsumeGrant(ctx, g.ID, now.Add(e.cfg.Grant.ReuseWindow)); err != nil {
		slog.Warn("could not mark grant consumed", "grant", g.ID, "err", err)
	}

	return relay.Decision{
		Allow:    true,
		Backend:  target.Addr(),
		GrantID:  g.ID,
		TargetID: target.ID,
	}
}

// Review is the JIT path: no grant exists, so we ask a human.
//
// The cookie only decides who gets asked. Approval is the factor, and NLA
// against the real Windows box still happens afterwards.
func (e *Engine) Review(ctx context.Context, srcIP net.IP, cr *x224.ConnectionRequest) relay.Decision {
	if !e.cfg.JIT.Enabled {
		return relay.Decision{Reason: "direct connections are disabled"}
	}
	if e.sender == nil {
		return relay.Decision{Reason: "no approval channel is configured"}
	}
	if cr.Cookie == "" {
		return relay.Decision{Reason: "client sent no username, cannot route an approval"}
	}

	user, err := e.db.UserByRDPHint(ctx, cr.Cookie)
	if err != nil {
		// Say the same thing as a denial: a prober must not be able to
		// enumerate accounts by watching how long we take to refuse.
		return relay.Decision{Reason: "no approval possible for this request"}
	}

	target, err := e.jitTarget(ctx, user)
	if err != nil {
		return relay.Decision{Reason: "no target available for this account"}
	}
	if ok, err := e.db.CanReach(ctx, user, target.ID); err != nil || !ok {
		return relay.Decision{Reason: "no approval possible for this request"}
	}

	reqID, err := e.db.CreateJITRequest(ctx, cr.Cookie, user.ID, target.ID, e.key(srcIP))
	if err != nil {
		slog.Error("could not record jit request", "err", err)
		return relay.Decision{Reason: "could not record the request"}
	}

	e.audit(ctx, audit.Entry{
		Actor: user.Username, Action: audit.ActionJITRequested,
		Object: target.Name, SrcIP: srcIP.String(),
		Detail: map[string]any{"hint": cr.Cookie},
	})

	// Wake while the human decides. If they say no we simply woke a machine,
	// which costs nothing and is not a security event.
	go e.wake(context.WithoutCancel(ctx), target)

	approved, err := e.sender.Approve(ctx, user.Username, srcIP.String(), target.Name)
	switch {
	case err != nil && ctx.Err() != nil:
		e.db.SetJITState(ctx, reqID, "timeout", "hold expired")
		e.audit(ctx, audit.Entry{Actor: user.Username, Action: audit.ActionJITTimeout, Object: target.Name, SrcIP: srcIP.String()})
		return relay.Decision{Reason: "approval timed out"}
	case err != nil:
		slog.Warn("approval channel failed", "user", user.Username, "err", err)
		e.db.SetJITState(ctx, reqID, "denied", "approval channel error")
		return relay.Decision{Reason: "approval channel unavailable"}
	case !approved:
		e.db.SetJITState(ctx, reqID, "denied", "user declined")
		e.audit(ctx, audit.Entry{Actor: user.Username, Action: audit.ActionJITDenied, Object: target.Name, SrcIP: srcIP.String()})
		return relay.Decision{Reason: "approval declined"}
	}

	// Approved, but the machine still has to be up before we can forward.
	if err := e.waitReady(ctx, target); err != nil {
		e.db.SetJITState(ctx, reqID, "timeout", "target did not wake")
		return relay.Decision{Reason: "target did not come up in time"}
	}

	g, err := e.issue(ctx, user, target, e.key(srcIP), "jit")
	if err != nil {
		return relay.Decision{Reason: "could not issue a grant"}
	}

	e.db.SetJITState(ctx, reqID, "approved", "push")
	e.audit(ctx, audit.Entry{
		Actor: user.Username, Action: audit.ActionJITApproved,
		Object: target.Name, SrcIP: srcIP.String(),
	})

	return relay.Decision{Allow: true, Backend: target.Addr(), GrantID: g, TargetID: target.ID}
}

// jitTarget picks the machine for a connection that could not name one.
func (e *Engine) jitTarget(ctx context.Context, u *store.User) (*store.Target, error) {
	targets, err := e.db.ListTargetsForUser(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets available")
	}

	if name := e.cfg.JIT.DefaultTarget; name != "" {
		for i := range targets {
			if targets[i].Name == name {
				return &targets[i], nil
			}
		}
	}
	// Only unambiguous when there is exactly one choice.
	if len(targets) > 1 {
		return nil, errors.New("account has several targets and none is configured as the default")
	}
	return &targets[0], nil
}

/* ------------------------------------------------------- portal path --- */

// Unlock is what the web portal calls after MFA succeeds. It is the only way
// a grant is created on the portal path.
func (e *Engine) Unlock(ctx context.Context, u *store.User, targetID int64, srcIP net.IP) (*store.Target, int64, error) {
	ok, err := e.db.CanReach(ctx, u, targetID)
	if err != nil {
		return nil, 0, fmt.Errorf("check access: %w", err)
	}
	if !ok {
		e.audit(ctx, audit.Entry{
			Actor: u.Username, Action: audit.ActionGrantDenied,
			SrcIP: srcIP.String(), Detail: map[string]any{"target_id": targetID},
		})
		return nil, 0, errors.New("not allowed to reach this target")
	}

	target, err := e.db.TargetByID(ctx, targetID)
	if err != nil {
		return nil, 0, fmt.Errorf("load target: %w", err)
	}

	id, err := e.issue(ctx, u, target, e.key(srcIP), "portal")
	if err != nil {
		return nil, 0, err
	}

	e.audit(ctx, audit.Entry{
		Actor: u.Username, Action: audit.ActionGrantIssued, Object: target.Name,
		SrcIP: srcIP.String(), Detail: map[string]any{"ttl_s": int(e.cfg.Grant.TTL.Seconds())},
	})

	go e.wake(context.WithoutCancel(ctx), target)
	return target, id, nil
}

func (e *Engine) issue(ctx context.Context, u *store.User, t *store.Target, ipKey, mode string) (int64, error) {
	now := time.Now()

	id, err := e.db.CreateGrant(ctx, store.Grant{
		UserID:    u.ID,
		TargetID:  t.ID,
		SrcIP:     ipKey,
		Mode:      mode,
		CreatedAt: now,
		ExpiresAt: now.Add(e.cfg.Grant.TTL),
	}, "")
	if err != nil {
		return 0, fmt.Errorf("issue grant: %w", err)
	}
	return id, nil
}

/* -------------------------------------------------------------- wake --- */

// Status reports what the dashboard shows for a target.
func (e *Engine) Status(ctx context.Context, t *store.Target) string {
	e.wakeMu.Lock()
	_, busy := e.waking[t.ID]
	e.wakeMu.Unlock()

	if busy {
		return "waking"
	}
	if wol.Alive(ctx, t.Addr(), 700*time.Millisecond) {
		return "online"
	}
	return "offline"
}

// wake sends the magic packet and waits for RDP to answer. Concurrent callers
// share one attempt.
func (e *Engine) wake(ctx context.Context, t *store.Target) {
	e.wakeMu.Lock()
	if st, busy := e.waking[t.ID]; busy {
		e.wakeMu.Unlock()
		<-st.done
		return
	}
	st := &wakeState{started: time.Now(), done: make(chan struct{})}
	e.waking[t.ID] = st
	e.wakeMu.Unlock()

	defer func() {
		e.wakeMu.Lock()
		delete(e.waking, t.ID)
		e.wakeMu.Unlock()
		close(st.done)
	}()

	// Already up: nothing to do.
	if wol.Alive(ctx, t.Addr(), time.Second) {
		return
	}

	mac, err := wol.ParseMAC(t.MAC)
	if err != nil {
		slog.Error("target has an unusable MAC", "target", t.Name, "mac", t.MAC, "err", err)
		st.err = err
		return
	}

	if err := e.waker.Send(mac, t.WoLBroadcast, t.WoLPort); err != nil {
		slog.Error("magic packet failed", "target", t.Name, "err", err)
		st.err = err
		return
	}
	e.audit(ctx, audit.Entry{
		Action: audit.ActionWolSent, Object: t.Name,
		Detail: map[string]any{"mac": t.MAC, "broadcast": t.WoLBroadcast},
	})

	boot, cancel := context.WithTimeout(ctx, time.Duration(t.BootTimeoutS)*time.Second)
	defer cancel()

	if err := e.prober.WaitReady(boot, t.Addr()); err != nil {
		st.err = err
		e.audit(ctx, audit.Entry{Action: audit.ActionTargetTimeout, Object: t.Name})
		return
	}

	e.audit(ctx, audit.Entry{
		Action: audit.ActionTargetOnline, Object: t.Name,
		Detail: map[string]any{"took_s": int(time.Since(st.started).Seconds())},
	})
}

// TestWake fires a magic packet on demand, for the "test MAC" button. It does
// not wait for the machine and issues no grant.
func (e *Engine) TestWake(ctx context.Context, t *store.Target) error {
	mac, err := wol.ParseMAC(t.MAC)
	if err != nil {
		return fmt.Errorf("target has an unusable MAC address: %w", err)
	}
	if err := e.waker.Send(mac, t.WoLBroadcast, t.WoLPort); err != nil {
		return fmt.Errorf("could not send the magic packet: %w", err)
	}
	return nil
}

// waitReady blocks until the target answers, joining an in-flight wake.
func (e *Engine) waitReady(ctx context.Context, t *store.Target) error {
	e.wakeMu.Lock()
	st := e.waking[t.ID]
	e.wakeMu.Unlock()

	if st != nil {
		select {
		case <-st.done:
			return st.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return e.prober.WaitReady(ctx, t.Addr())
}

func (e *Engine) audit(ctx context.Context, entry audit.Entry) {
	if err := e.log.Append(ctx, entry); err != nil {
		slog.Error("audit append failed", "action", entry.Action, "err", err)
	}
}

/* ---------------------------------------------------- relay.Recorder --- */

func (e *Engine) Opened(ctx context.Context, d relay.Decision, srcIP net.IP) int64 {
	id, err := e.db.OpenRDPSession(ctx, d.GrantID, d.TargetID, srcIP.String())
	if err != nil {
		slog.Error("could not record session start", "err", err)
		return 0
	}

	name := ""
	if t, err := e.db.TargetByID(ctx, d.TargetID); err == nil {
		name = t.Name
	}
	e.audit(ctx, audit.Entry{
		Action: audit.ActionRelayOpen, Object: name, SrcIP: srcIP.String(),
		Detail: map[string]any{"session": id},
	})
	return id
}

func (e *Engine) Closed(ctx context.Context, sessionID int64, in, out int64, reason string) {
	if sessionID == 0 {
		return
	}
	if err := e.db.CloseRDPSession(ctx, sessionID, in, out, reason); err != nil {
		slog.Error("could not record session end", "session", sessionID, "err", err)
	}
	e.audit(ctx, audit.Entry{
		Action: audit.ActionRelayClose,
		Detail: map[string]any{"session": sessionID, "bytes_in": in, "bytes_out": out, "reason": reason},
	})
}

func (e *Engine) Rejected(ctx context.Context, srcIP net.IP, reason, hint string) {
	detail := map[string]any{"reason": reason}
	if hint != "" {
		detail["hint"] = hint
	}
	e.audit(ctx, audit.Entry{Action: audit.ActionRelayRejected, SrcIP: srcIP.String(), Detail: detail})
}

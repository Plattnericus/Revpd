package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/wol"
)

/*
   The rest of the management surface: waking machines, live sessions, the
   access matrix, passkeys, configuration and diagnostics.

   Every one of these has to work when things are already going wrong, so they
   all degrade rather than fail: a command that needs the database says so
   instead of returning a stack trace, and doctor keeps checking after the
   first problem it finds.
*/

/* ----------------------------------------------------------------- wake --- */

// cmdWake sends the magic packet without opening a session, which is what you
// want when testing wiring or starting a machine for something else.
func cmdWake(args []string) error {
	name, flags := splitName(args)
	if name == "" {
		return errors.New("usage: revpd wake NAME [--wait]")
	}

	cfg, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	t, err := db.TargetByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no machine called %q — see: revpd target list", name)
	}

	mac, err := wol.ParseMAC(t.MAC)
	if err != nil {
		return fmt.Errorf("%q has an unusable MAC address (%s): %w", name, t.MAC, err)
	}

	if wol.Alive(ctx, t.Addr(), time.Second) {
		okf("%s is already awake", name)
		return nil
	}

	sender := wol.Sender{Repeat: cfg.WoL.Repeat}
	if err := sender.Send(mac, t.WoLBroadcast, t.WoLPort); err != nil {
		return fmt.Errorf("could not send the wake-up: %w", err)
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionWolSent, Object: name})
	okf("wake-up sent to %s (%s)", name, t.MAC)

	if !has(flags, "--wait", "-w") {
		sayf("\n  Add --wait to watch it come up.\n")
		return nil
	}

	// Watching is the useful part: it turns "did that work?" into an answer.
	sayf("\n  Waiting for %s to answer on %s\n", name, t.Addr())

	deadline := time.Now().Add(time.Duration(t.BootTimeoutS) * time.Second)
	for time.Now().Before(deadline) {
		if wol.Alive(ctx, t.Addr(), time.Second) {
			okf("%s is up after %ds", name, t.BootTimeoutS-int(time.Until(deadline).Seconds()))
			return nil
		}
		time.Sleep(time.Second)
	}

	warnf("%s did not answer within %d seconds", name, t.BootTimeoutS)
	sayf("\n  Common causes:\n" +
		"    Fast Startup is still on in Windows  (powercfg /hibernate off)\n" +
		"    Wake-on-LAN is off in the BIOS or the network adapter\n" +
		"    The broadcast address is wrong for this subnet\n\n")
	return nil
}

/* ------------------------------------------------------------- sessions --- */

func cmdSessions(args []string) error {
	if len(args) > 0 && (args[0] == "kick" || args[0] == "close") {
		return sessionKick(args[1:])
	}

	_, db, _, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	live, err := db.ListLiveSessions(context.Background())
	if err != nil {
		return err
	}
	if len(live) == 0 {
		sayf("\n  Nobody is connected right now.\n\n")
		return nil
	}

	fmt.Printf("\n  %-6s %-16s %-20s %-18s %s\n", "ID", "USER", "MACHINE", "FROM", "SINCE")
	for _, s := range live {
		fmt.Printf("  %-6d %-16s %-20s %-18s %s\n",
			s.ID, s.Username, s.Target, s.SrcIP, since(s.StartedAt))
	}
	sayf("\n  Disconnect one with:  revpd sessions kick ID\n\n")
	return nil
}

func sessionKick(args []string) error {
	name, _ := splitName(args)
	if name == "" {
		return errors.New("usage: revpd sessions kick ID")
	}

	id, err := parseID(name)
	if err != nil {
		return fmt.Errorf("%q is not a session id — see: revpd sessions", name)
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.CloseRDPSession(ctx, id, 0, 0, "disconnected from the command line"); err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{
		Actor: "cli", Action: audit.ActionRelayClose,
		Detail: map[string]any{"session": id, "reason": "kicked"},
	})

	okf("session %d marked closed", id)
	// Being honest about what this does and does not do.
	sayf("\n  %sThe record is closed. If the connection is still live it will\n"+
		"  drop when it next goes idle, or immediately on:  revpd service restart%s\n\n", dim, reset)
	return nil
}

/* --------------------------------------------------------------- access --- */

// cmdAccess manages who may reach which machine — the matrix that decides
// everything, and previously only reachable through the web interface.
func cmdAccess(args []string) error {
	if len(args) == 0 {
		return accessList()
	}

	switch args[0] {
	case "list", "ls":
		return accessList()
	case "grant", "add":
		return accessChange(args[1:], true)
	case "revoke", "rm", "remove":
		return accessChange(args[1:], false)
	default:
		return fmt.Errorf("usage: revpd access list|grant USER MACHINE|revoke USER MACHINE")
	}
}

func accessList() error {
	_, db, _, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	users, err := db.ListUsers(ctx)
	if err != nil {
		return err
	}
	targets, err := db.ListTargets(ctx)
	if err != nil {
		return err
	}

	if len(users) == 0 || len(targets) == 0 {
		sayf("\n  Nothing to show yet — add a user and a machine first.\n\n")
		return nil
	}

	sayf("\n")
	for _, u := range users {
		var reachable []string
		for _, t := range targets {
			if ok, err := db.CanReach(ctx, &u, t.ID); err == nil && ok {
				reachable = append(reachable, t.Name)
			}
		}

		switch {
		case u.IsAdmin():
			// Admins reach everything by role, which is worth saying out loud
			// rather than listing every machine.
			fmt.Printf("  %-16s %severything (administrator)%s\n", u.Username, dim, reset)
		case len(reachable) == 0:
			fmt.Printf("  %-16s %snothing yet%s\n", u.Username, dim, reset)
		default:
			fmt.Printf("  %-16s %s\n", u.Username, strings.Join(reachable, ", "))
		}
	}
	sayf("\n  revpd access grant USER MACHINE\n\n")
	return nil
}

func accessChange(args []string, grant bool) error {
	var names []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	if len(names) < 2 {
		verb := "grant"
		if !grant {
			verb = "revoke"
		}
		return fmt.Errorf("usage: revpd access %s USER MACHINE", verb)
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	u, err := db.UserByName(ctx, names[0])
	if err != nil {
		return fmt.Errorf("no user called %q — see: revpd user list", names[0])
	}
	t, err := db.TargetByName(ctx, names[1])
	if err != nil {
		return fmt.Errorf("no machine called %q — see: revpd target list", names[1])
	}

	if grant {
		err = db.GrantTargetAccess(ctx, u.ID, t.ID)
	} else {
		err = db.RevokeTargetAccess(ctx, u.ID, t.ID)
		// Revoking has to take effect now, not when a grant happens to expire.
		db.RevokeGrantsForUser(ctx, u.ID)
	}
	if err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{
		Actor: "cli", Action: audit.ActionUserUpdated, Object: u.Username,
		Detail: map[string]any{"target": t.Name, "granted": grant},
	})

	if grant {
		okf("%s can now reach %s", u.Username, t.Name)
	} else {
		okf("%s can no longer reach %s", u.Username, t.Name)
	}
	return nil
}

/* ------------------------------------------------------------- passkeys --- */

func cmdPasskey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: revpd passkey list USER | revpd passkey rm USER ID")
	}

	switch args[0] {
	case "list", "ls":
		return passkeyList(args[1:])
	case "rm", "remove", "delete":
		return passkeyRemove(args[1:])
	default:
		return fmt.Errorf("unknown: revpd passkey %s", args[0])
	}
}

func passkeyList(args []string) error {
	name, _ := splitName(args)
	if name == "" {
		return errors.New("usage: revpd passkey list USER")
	}

	_, db, _, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	u, err := db.UserByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no user called %q", name)
	}

	keys, err := db.PasskeysFor(ctx, u.ID)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		sayf("\n  %s has no passkeys.\n\n", name)
		return nil
	}

	fmt.Printf("\n  %-6s %-24s %s\n", "ID", "NAME", "ADDED")
	for _, k := range keys {
		fmt.Printf("  %-6d %-24s %s\n", k.ID, k.Name, k.CreatedAt.Format("2 Jan 2006"))
	}
	fmt.Println()
	return nil
}

func passkeyRemove(args []string) error {
	var names []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	if len(names) < 2 {
		return errors.New("usage: revpd passkey rm USER ID")
	}

	id, err := parseID(names[1])
	if err != nil {
		return fmt.Errorf("%q is not a passkey id — see: revpd passkey list %s", names[1], names[0])
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	u, err := db.UserByName(ctx, names[0])
	if err != nil {
		return fmt.Errorf("no user called %q", names[0])
	}

	// Removing someone's only factor would lock them out of their own gateway.
	if len(u.TOTPSecretEnc) == 0 {
		if n, err := db.CountPasskeys(ctx, u.ID); err == nil && n <= 1 {
			return fmt.Errorf("that is %s's only second factor — set up an authenticator first:\n  revpd user reset %s",
				u.Username, u.Username)
		}
	}

	if err := db.DeletePasskey(ctx, u.ID, id); err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{
		Actor: "cli", Action: audit.ActionUserUpdated, Object: u.Username,
		Detail: map[string]any{"removed_passkey": id},
	})

	okf("removed passkey %d from %s", id, u.Username)
	return nil
}

/* --------------------------------------------------------------- config --- */

// cmdConfig shows what the gateway is actually running with, which is not
// always what the file says once the environment has had its turn.
func cmdConfig(args []string) error {
	if len(args) > 0 && (args[0] == "path" || args[0] == "where") {
		fmt.Println(defaultConfigPath())
		return nil
	}
	if len(args) > 0 && args[0] == "edit" {
		return configEdit()
	}

	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return err
	}

	sayf("\n  %sIn effect%s %s(%s plus the environment)%s\n\n",
		bold, reset, dim, defaultConfigPath(), reset)

	fmt.Printf("  Hostname            %s\n", cfg.Web.Hostname)
	fmt.Printf("  Web interface       %s\n", cfg.Web.Listen)
	fmt.Printf("  Remote Desktop      %s\n", cfg.Relay.Listen)
	fmt.Printf("  Data directory      %s\n", cfg.DataDir)
	fmt.Println()
	fmt.Printf("  Login from RDP      %s\n", onOff(cfg.RDPLogin.Enabled))
	fmt.Printf("  Push approvals      %s\n", onOff(cfg.JIT.Enabled))
	fmt.Printf("  RD Gateway (443)    %s\n", onOff(cfg.RDGW.Enabled))
	fmt.Println()
	fmt.Printf("  Access valid for    %s\n", cfg.Grant.TTL)
	fmt.Printf("  Reconnect window    %s\n", cfg.Grant.ReuseWindow)
	fmt.Printf("  Failed attempts     %d before lockout\n", cfg.Auth.MaxFailures)
	fmt.Println()

	if cfg.Web.TLSCert == "" {
		fmt.Printf("  Certificate         %sself-signed (browsers will warn)%s\n", dim, reset)
	} else {
		fmt.Printf("  Certificate         %s\n", cfg.Web.TLSCert)
	}

	host, _, _ := cfg.Duo()
	if host == "" {
		fmt.Printf("  Duo                 %snot configured%s\n", dim, reset)
	} else {
		fmt.Printf("  Duo                 %s\n", host)
	}

	sayf("\n  Edit it with:  revpd config edit\n\n")
	return nil
}

func configEdit() error {
	if err := needRoot("editing the configuration", "config", "edit"); err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		// Whichever of these exists; nano first because it tells you how to
		// quit, which vi famously does not.
		for _, candidate := range []string{"nano", "vim", "vi"} {
			if _, err := lookPath(candidate); err == nil {
				editor = candidate
				break
			}
		}
	}
	if editor == "" {
		return fmt.Errorf("no editor found — set EDITOR, or edit %s by hand", defaultConfigPath())
	}

	if err := runInteractive(editor, defaultConfigPath()); err != nil {
		return err
	}

	// A file that does not parse would stop the service from starting, so
	// check before anyone restarts it.
	if _, err := config.Load(defaultConfigPath()); err != nil {
		warnf("the file has a problem:")
		sayf("\n  %v\n\n", err)
		sayf("  Fix it before restarting, or the gateway will not come back up.\n\n")
		return nil
	}

	okf("the file is valid")
	sayf("\n  Apply it with:  revpd service restart\n\n")
	return nil
}

/* --------------------------------------------------------------- doctor --- */

// check is one diagnosis. Keeping the result and the advice together means a
// problem always arrives with something to do about it.
type check struct {
	name   string
	status string // "ok", "warn", "fail"
	detail string
	fix    string
}

// cmdDoctor looks for the things that actually go wrong, and says how to fix
// each one.
//
// It keeps going after a failure on purpose: someone running this has a
// problem already, and finding all of them in one pass beats fixing them one
// restart at a time.
func cmdDoctor() error {
	sayf("\n  %sChecking%s\n\n", bold, reset)

	var checks []check
	add := func(c check) {
		checks = append(checks, c)
		symbol, colour := "✓", green
		switch c.status {
		case "warn":
			symbol, colour = "!", yellow
		case "fail":
			symbol, colour = "✗", rd
		}

		fmt.Printf("  %s%s%s %s", colour, symbol, reset, c.name)
		if c.detail != "" {
			fmt.Printf("  %s%s%s", dim, c.detail, reset)
		}
		fmt.Println()
	}

	// ── configuration ────────────────────────────────────────────────────
	cfg, cfgErr := config.Load(defaultConfigPath())
	if cfgErr != nil {
		add(check{"Configuration", "fail", cfgErr.Error(),
			"Fix " + defaultConfigPath() + ", or reinstall to get a fresh one."})
		summarise(checks)
		return nil // nothing else can be checked without it
	}
	add(check{"Configuration", "ok", defaultConfigPath(), ""})

	// ── the master key ───────────────────────────────────────────────────
	if cfg.MasterKey() == "" {
		add(check{"Encryption key", "fail", "not set",
			"Every second factor is encrypted with it. Check " + installConfDir + "/.env"})
	} else {
		add(check{"Encryption key", "ok", "", ""})
	}

	// ── the database ─────────────────────────────────────────────────────
	db, log, _, dbErr := openWith(cfg)
	if dbErr != nil {
		add(check{"Database", "fail", dbErr.Error(),
			"Check that " + cfg.DataDir + " exists and the revpd user can write to it."})
		summarise(checks)
		return nil
	}
	defer db.Close()
	add(check{"Database", "ok", filepath.Join(cfg.DataDir, "revpd.db"), ""})

	ctx := context.Background()

	// ── the audit chain ──────────────────────────────────────────────────
	if brk, n, err := log.Verify(ctx); err != nil {
		add(check{"Audit trail", "warn", err.Error(), ""})
	} else if brk != nil {
		add(check{"Audit trail", "fail", fmt.Sprintf("broken at entry %d", brk.ID),
			"Someone edited the log. " + brk.Reason})
	} else {
		add(check{"Audit trail", "ok", fmt.Sprintf("%d entries, intact", n), ""})
	}

	// ── accounts ─────────────────────────────────────────────────────────
	users, _ := db.ListUsers(ctx)

	admins, noFactor := 0, []string{}
	for _, u := range users {
		if u.IsAdmin() {
			admins++
		}
		passkeys, _ := db.CountPasskeys(ctx, u.ID)
		codes, _ := db.CountBackupCodes(ctx, u.ID)
		if len(u.TOTPSecretEnc) == 0 && passkeys == 0 && codes == 0 {
			noFactor = append(noFactor, u.Username)
		}
	}

	switch {
	case len(users) == 0:
		add(check{"Accounts", "fail", "none",
			"Nobody can sign in. Create one:  revpd user add NAME --admin"})
	case admins == 0:
		add(check{"Accounts", "warn", fmt.Sprintf("%d, none an administrator", len(users)),
			"Nobody can manage the gateway from the web interface."})
	default:
		add(check{"Accounts", "ok", fmt.Sprintf("%d, %d administrator(s)", len(users), admins), ""})
	}

	if len(noFactor) > 0 {
		add(check{"Second factors", "warn",
			strings.Join(noFactor, ", ") + " cannot sign in",
			"Set one up:  revpd user reset " + noFactor[0]})
	} else if len(users) > 0 {
		add(check{"Second factors", "ok", "everyone is enrolled", ""})
	}

	// ── machines ─────────────────────────────────────────────────────────
	targets, _ := db.ListTargets(ctx)
	if len(targets) == 0 {
		add(check{"Machines", "warn", "none",
			"Add one:  revpd target add \"Office PC\" 192.168.1.40 aa:bb:cc:dd:ee:ff"})
	} else {
		add(check{"Machines", "ok", fmt.Sprintf("%d", len(targets)), ""})
	}

	// A MAC that does not parse means Wake-on-LAN silently never works.
	for _, t := range targets {
		if _, err := wol.ParseMAC(t.MAC); err != nil {
			add(check{"MAC address", "fail", fmt.Sprintf("%s has %q", t.Name, t.MAC),
				"Wake-on-LAN cannot work for it. Fix it:  revpd target rm " + t.Name})
		}
	}

	// And a machine nobody can reach is a machine nobody can use.
	for _, t := range targets {
		reachable := false
		for _, u := range users {
			if ok, _ := db.CanReach(ctx, &u, t.ID); ok {
				reachable = true
				break
			}
		}
		if !reachable {
			add(check{"Access", "warn", t.Name + " is not shared with anyone",
				"Grant it:  revpd access grant USER \"" + t.Name + "\""})
		}
	}

	// ── the service and its ports ────────────────────────────────────────
	if runtime.GOOS == "linux" {
		state := serviceState()
		switch {
		case strings.HasPrefix(state, "running"):
			add(check{"Service", "ok", state, ""})
		case state == "not installed":
			add(check{"Service", "warn", state, "Reinstall to set it up as a service."})
		default:
			add(check{"Service", "fail", state, "Start it:  revpd service start   then:  revpd logs"})
		}
	}

	for _, p := range []struct{ what, addr string }{
		{"Remote Desktop port", cfg.Relay.Listen},
		{"Web interface port", cfg.Web.Listen},
	} {
		if listening(p.addr) {
			add(check{p.what, "ok", p.addr + " is accepting connections", ""})
		} else {
			add(check{p.what, "warn", "nothing is listening on " + p.addr,
				"Normal if the service is stopped. Otherwise check:  revpd logs"})
		}
	}

	// ── file permissions ─────────────────────────────────────────────────
	if runtime.GOOS == "linux" {
		envPath := filepath.Join(installConfDir, ".env")
		if info, err := os.Stat(envPath); err == nil {
			if info.Mode().Perm()&0o004 != 0 {
				add(check{"Key file permissions", "fail",
					fmt.Sprintf("%s is world-readable (%v)", envPath, info.Mode().Perm()),
					"Anyone on this machine can read every second factor. Fix:  chmod 640 " + envPath})
			} else {
				add(check{"Key file permissions", "ok", "", ""})
			}
		}
	}

	// ── certificate ──────────────────────────────────────────────────────
	if cfg.Web.TLSCert == "" {
		add(check{"Certificate", "warn", "self-signed",
			"Browsers warn, and passkeys still work. Point web.tls_cert at a real one to stop the warning."})
	} else if _, err := os.Stat(cfg.Web.TLSCert); err != nil {
		add(check{"Certificate", "fail", cfg.Web.TLSCert + " cannot be read",
			"The web interface will not start. Check the path and permissions."})
	} else {
		add(check{"Certificate", "ok", cfg.Web.TLSCert, ""})
	}

	summarise(checks)
	return nil
}

func summarise(checks []check) {
	var problems []check
	for _, c := range checks {
		if c.status != "ok" {
			problems = append(problems, c)
		}
	}

	if len(problems) == 0 {
		sayf("\n  %s✓ Everything looks right.%s\n\n", green, reset)
		return
	}

	sayf("\n  %sWhat to do%s\n\n", bold, reset)
	for _, c := range problems {
		if c.fix == "" {
			continue
		}
		colour := yellow
		if c.status == "fail" {
			colour = rd
		}
		sayf("  %s%s%s\n    %s\n\n", colour, c.name, reset, c.fix)
	}
}

// listening reports whether something already holds an address, which is how
// we tell "the service is up" from "the port is free".
func listening(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

/* ----------------------------------------------------------------- misc --- */

// cmdAuditList shows the log, which used to need the web interface.
func cmdAuditList(args []string) error {
	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	q := audit.Query{Limit: 40}
	if v := valueOf(args, "--action", "-action"); v != "" {
		q.Action = v
	}
	if v := valueOf(args, "--user", "-user"); v != "" {
		q.Actor = v
	}
	if has(args, "--all", "-all") {
		q.Limit = 500
	}

	entries, err := log.List(context.Background(), q)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		sayf("\n  Nothing recorded yet.\n\n")
		return nil
	}

	sayf("\n")
	// Oldest first reads like a story; newest first reads like a puzzle.
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]

		colour := dim
		switch {
		case strings.HasSuffix(e.Action, ".fail"), strings.HasSuffix(e.Action, ".rejected"),
			strings.HasSuffix(e.Action, ".denied"), e.Action == "lockout":
			colour = rd
		case strings.HasSuffix(e.Action, ".ok"), e.Action == "relay.open":
			colour = green
		}

		fmt.Printf("  %s%s%s  %s%-22s%s %-14s %s\n",
			dim, e.TS.Format("02 Jan 15:04:05"), reset,
			colour, e.Action, reset,
			truncate(e.Actor, 14), truncate(e.Object, 24))
	}

	sayf("\n  %d entries. Filter with --user NAME or --action NAME, --all for more.\n\n", len(entries))
	return nil
}

func since(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 2 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func parseID(s string) (int64, error) {
	var n int64
	if s == "" {
		return 0, errors.New("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}

var _ = store.User{}

// Command revpd is the MFA gateway for RDP with Wake-on-LAN.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/plattnericus/revpd/internal/api"
	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/mfa/duo"
	"github.com/plattnericus/revpd/internal/netcheck"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/update"
	"github.com/plattnericus/revpd/internal/web"
)

var version = "dev" // set with -ldflags at release time

func main() {
	err := run()

	// The action ran as root in a child process, which has already printed
	// whatever it had to say. Repeating it here would be noise.
	if errors.Is(err, errElevated) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "revpd:", err)
		os.Exit(1)
	}
}

func run() error {
	// Bare `revpd` in a terminal opens the menu. Anywhere else — a pipe, a
	// script, a cron job — it prints help and returns, because a prompt that
	// nobody can answer would hang forever.
	if len(os.Args) < 2 {
		if isInteractive() {
			return runMenu()
		}
		usage()
		return nil
	}

	// Most commands read /etc/revpd, which only root may. Ask for the rights
	// up front rather than failing later on a path nobody mentioned.
	if err := elevateIfNeeded(os.Args[1:]); err != nil {
		return err
	}

	switch os.Args[1] {
	// Everyday management.
	case "menu":
		return runMenu()
	case "user":
		return cmdUser(os.Args[2:])
	case "target", "machine":
		return cmdTarget(os.Args[2:])
	case "access":
		return cmdAccess(os.Args[2:])
	case "passkey", "passkeys":
		return cmdPasskey(os.Args[2:])
	case "wake":
		return cmdWake(os.Args[2:])
	case "sessions", "session":
		return cmdSessions(os.Args[2:])
	case "service":
		return cmdService(os.Args[2:])
	case "logs":
		return cmdLogs(os.Args[2:])
	case "status":
		return cmdStatus()
	case "config":
		return cmdConfig(os.Args[2:])
	case "doctor", "check":
		return cmdDoctor()
	case "update", "upgrade":
		return cmdUpdate(os.Args[2:])
	case "backup":
		return cmdBackup(os.Args[2:])
	case "restore":
		return cmdRestore(os.Args[2:])
	case "uninstall":
		// errRemoved means it worked; only the menu treats it as a signal.
		if err := cmdUninstall(os.Args[2:]); err != nil && !errors.Is(err, errRemoved) {
			return err
		}
		return nil

	// The gateway itself.
	case "serve":
		return cmdServe(os.Args[2:])
	case "audit":
		// `audit verify` checks the chain; bare `audit` shows the log.
		if len(os.Args) > 2 && os.Args[2] == "verify" {
			return cmdAudit(os.Args[2:])
		}
		return cmdAuditList(os.Args[2:])

	// Kept working because install.sh calls them, and so does anyone who
	// wrote a script against an earlier version.
	case "genkey":
		return cmdGenKey()
	case "useradd":
		return cmdUserAdd(os.Args[2:])
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "targetadd":
		return cmdTargetAdd(os.Args[2:])

	case "version", "-v", "--version":
		fmt.Println("revpd", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `revpd — MFA gateway for RDP with Wake-on-LAN

  revpd                            open the menu
  revpd doctor                     check everything and say what to fix

People
  revpd user add NAME [--admin]    create an account
  revpd user list
  revpd user rm NAME
  revpd user reset NAME            new authenticator QR and backup codes
  revpd user lock|unlock NAME      block or restore sign-in
  revpd passkey list USER
  revpd passkey rm USER ID

Machines
  revpd target add NAME IP MAC [--for USER]
  revpd target list
  revpd target rm NAME
  revpd wake NAME [--wait]         send the wake-up signal now

Who can reach what
  revpd access                     the whole matrix
  revpd access grant USER MACHINE
  revpd access revoke USER MACHINE

Running it
  revpd status                     a one-screen overview
  revpd service start|stop|restart|status
  revpd logs [-f]
  revpd config [edit]              what it is actually running with
  revpd sessions                   who is connected right now
  revpd sessions kick ID

History
  revpd audit                      what has happened
  revpd audit verify               prove the log was not tampered with

Keeping it current
  revpd update                     is there a newer release?
  revpd update install [VERSION]   download, verify and install it
  revpd update rollback            go back to the previous version

Moving and removing
  revpd backup [FILE]              everything in one encrypted file
  revpd restore [FILE]
  revpd uninstall [--keep-data]    remove Revpd from this machine

  revpd version

Settings live in /etc/revpd/revpd.yaml, secrets in /etc/revpd/.env.
`)
}

/* --------------------------------------------------------------- serve --- */

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfigPath(), "path to config file")
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	setupLogging(*debug)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, log, sealer, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	// Sessions left open by a crash are not live any more.
	if err := db.MarkStaleSessionsClosed(ctx); err != nil {
		slog.Warn("could not tidy stale sessions", "err", err)
	}

	// Settings changed in the web interface are stored in the database and
	// layered over the file here, once, before anything reads the result.
	//
	// The file is never rewritten: the service runs with /etc read-only, and
	// silently editing a file somebody else administers would be worse than
	// keeping the two apart and showing both.
	fileCfg := cfg
	if overrides, err := db.AllSettings(ctx); err != nil {
		slog.Warn("could not read stored settings, using the file alone", "err", err)
	} else if len(overrides) > 0 {
		merged, unknown, err := config.Apply(cfg, overrides)
		for _, k := range unknown {
			slog.Warn("a stored setting no longer exists and is being ignored", "key", k)
		}
		if err != nil {
			// The file on its own is known-good, so the gateway still starts.
			// Refusing to boot over a bad stored value would leave no way in
			// to correct it.
			slog.Error("stored settings are not valid and have been ignored", "err", err)
		} else {
			cfg = merged
			slog.Info("applied settings from the web interface", "count", len(overrides))
		}
	}

	authMgr := auth.NewManager(db, auth.Options{
		TTL:         cfg.Auth.SessionTTL,
		Idle:        cfg.Auth.SessionIdle,
		MaxFailures: cfg.Auth.MaxFailures,
		LockoutBase: cfg.Auth.LockoutBase,
		LockoutMax:  cfg.Auth.LockoutMax,
	})

	// Push approvals. Nil when Duo is not configured, which the engine treats
	// as "push is unavailable" rather than an error.
	var approver policy.Approver
	if host, ikey, skey := cfg.Duo(); host != "" {
		client := duo.New(duo.Options{APIHost: host, IKey: ikey, SKey: skey})
		if client == nil {
			return errors.New("duo is partly configured: set REVPD_DUO_API_HOST, REVPD_DUO_IKEY and REVPD_DUO_SKEY together")
		}

		// Fail at startup rather than at the first push. A wrong key or a
		// clock more than a few minutes out both surface here.
		probe, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := client.Check(probe)
		cancel()
		if err != nil {
			return fmt.Errorf("duo rejected our credentials: %w", err)
		}

		approver = client
		slog.Info("duo push approvals enabled", "api_host", host)
	}

	engine := policy.New(db, log, cfg, approver).WithSecrets(sealer, authMgr)

	// The RDP-native login: credentials are typed into the Windows client and
	// the user is redirected on. This is the normal way in.
	var login relay.LoginHandler
	if cfg.RDPLogin.Enabled {
		cert, err := rdp.LoadOrCreateCert(cfg.DataDir, cfg.Web.Hostname, cfg.RDPLogin.TLSCert, cfg.RDPLogin.TLSKey)
		if err != nil {
			return err
		}
		login = rdp.NewLogin(rdp.Options{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
			HandshakeTimeout: cfg.RDPLogin.Timeout,
			StepTimeout:      cfg.RDPLogin.StepTimeout,
		}, engine)
	}

	// RDP data plane.
	relaySrv := relay.New(relay.Options{
		Listen:        cfg.Relay.Listen,
		JITEnabled:    cfg.JIT.Enabled,
		PeekTimeout:   cfg.JIT.PeekTimeout,
		HoldTimeout:   cfg.JIT.HoldTimeout,
		DialTimeout:   cfg.Relay.DialTimeout,
		IdleTimeout:   cfg.Relay.IdleTimeout,
		Tarpit:        cfg.Relay.Tarpit,
		MaxConnsPerIP: cfg.Relay.MaxConnsPerIP,
		Login:         login,
	}, engine, engine)

	errs := make(chan error, 2)
	go func() { errs <- relaySrv.Serve(ctx) }()

	// Self-update. The manager is created even when periodic checks are off,
	// so the button in the dashboard still works; only the timer is gated.
	updater, err := update.NewManager(update.Options{
		DataDir: cfg.DataDir,
		Version: version,
		Repo:    cfg.Update.Repo,
	})
	if err != nil {
		// Not fatal: a gateway that cannot update itself still gateways.
		slog.Warn("the updater is unavailable", "err", err)
	}

	// The portal, on the port a browser assumes where that is free. Binding
	// happens before anything is served so a clash is a startup error rather
	// than something discovered later.
	portal, err := config.Listen("tcp", cfg.Web.Listen, cfg.Web.ListenFallbacks)
	if err != nil {
		return fmt.Errorf("the web interface could not open a port: %w", err)
	}
	defer portal.Listener.Close()

	if portal.FellBack {
		slog.Warn("the web interface is not on its usual port",
			"listening_on", portal.Addr,
			"wanted", cfg.Web.Listen,
			"refused", strings.Join(portal.Tried, "; "))
	}

	// How the gateway looks from the internet, which its own sockets cannot
	// see: behind a router they only ever know the LAN. Display only — the
	// connect address, the .rdp file, the port-forward hint — and no
	// forwarding decision reads it, which is what makes it safe for part of
	// the answer to come from a stranger.
	publicAddr := netcheck.NewService(netcheck.ServiceOptions{
		Host:    cfg.PublicHost(),
		Detect:  cfg.Public.Detect,
		Refresh: cfg.Public.Refresh,
		Detector: netcheck.New(netcheck.Options{
			Resolvers: cfg.Public.Resolvers,
		}),
	})
	go publicAddr.Run(ctx)

	// Web portal.
	apiSrv := api.New(db, log, cfg, authMgr, engine, sealer, web.Handler()).
		WithUpdates(updater, version).
		WithPortal(portal.Addr).
		WithPublic(publicAddr).
		WithFileConfig(fileCfg)
	httpSrv := &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
	}

	// The portal always speaks TLS. Without a configured certificate one is
	// generated into the data directory rather than falling back to plain
	// HTTP: a session cookie must never travel in the clear, and passkeys
	// only work in a secure context at all.
	portalCert, err := rdp.LoadOrCreateCert(
		filepath.Join(cfg.DataDir, "web"), cfg.Web.Hostname, cfg.Web.TLSCert, cfg.Web.TLSKey)
	if err != nil {
		return fmt.Errorf("portal certificate: %w", err)
	}
	httpSrv.TLSConfig.Certificates = []tls.Certificate{portalCert}

	if cfg.Web.TLSCert == "" && cfg.PortalIsPublic() {
		slog.Warn("the portal is using a self-signed certificate — browsers will warn until you set web.tls_cert and web.tls_key",
			"listen", cfg.Web.Listen)
	}

	go func() {
		// The listener is already open and the certificates come from
		// TLSConfig, so both arguments stay empty.
		err := httpSrv.ServeTLS(portal.Listener, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	// Plain HTTP, serving nothing but a redirect to the portal. Somebody who
	// types the hostname without https:// would otherwise get a dead port and
	// conclude the gateway is down.
	redirectSrv := startHTTPRedirect(cfg, portal.Addr, errs)
	if redirectSrv != nil {
		defer redirectSrv.Close()
	}

	go housekeeping(ctx, db, authMgr, cfg)
	go apiSrv.RunAutoUpdate(ctx)

	slog.Info("revpd running",
		"version", version,
		"web", portal.Addr,
		"portal_url", config.PortalURL(cfg.Web.Hostname, portal.Addr),
		"relay", cfg.Relay.Listen,
		"hostname", cfg.Web.Hostname,
		"connect_from", netcheck.JoinHostPort(cfg.PublicHost(), cfg.PublicRDPPort(), 3389),
		"jit", cfg.JIT.Enabled)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil {
			return err
		}
	}

	slog.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdown)
	return nil
}

// startHTTPRedirect opens the plain-HTTP port and answers everything on it
// with a permanent redirect to the portal. Nil when it is turned off, or when
// the port could not be opened — a missing convenience is not worth refusing
// to start the gateway over.
func startHTTPRedirect(cfg config.Config, portalAddr string, errs chan<- error) *http.Server {
	if cfg.Web.HTTPListen == "" {
		return nil
	}

	bound, err := config.Listen("tcp", cfg.Web.HTTPListen, cfg.Web.HTTPListenFallbacks)
	if err != nil {
		slog.Warn("no plain-HTTP port could be opened, so http:// links will not redirect",
			"wanted", cfg.Web.HTTPListen, "err", err)
		return nil
	}

	portalPort := config.Port(portalAddr)

	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The host is taken from the request rather than from the config,
			// so this works whether the gateway is reached by name, by IP or
			// through a tunnel. Only the port is ours to decide.
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host == "" {
				host = cfg.Web.Hostname
			}

			target := "https://" + host
			if portalPort != "" && portalPort != "443" {
				target = "https://" + net.JoinHostPort(host, portalPort)
			}
			target += r.URL.RequestURI()

			// 308 rather than 301: it keeps the method and body, and it is not
			// cached as aggressively by browsers that saw an earlier setup.
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		}),
	}

	go func() {
		err := srv.Serve(bound.Listener)
		if !errors.Is(err, http.ErrServerClosed) {
			// Losing the redirect does not take the gateway down with it.
			slog.Warn("the plain-HTTP redirect stopped", "err", err)
		}
	}()

	slog.Info("redirecting plain HTTP to the portal", "listen", bound.Addr)
	return srv
}

// housekeeping trims what would otherwise grow forever.
func housekeeping(ctx context.Context, db *store.DB, am *auth.Manager, cfg config.Config) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := db.PurgeExpired(ctx, time.Now().Add(-24*time.Hour)); err != nil {
				slog.Warn("purge failed", "err", err)
			}
			if err := db.ExpirePendingJIT(ctx, time.Now().Add(-10*time.Minute)); err != nil {
				slog.Warn("jit sweep failed", "err", err)
			}
			am.SweepLockouts()
		}
	}
}

/* ---------------------------------------------------------------- setup --- */

func cmdGenKey() error {
	key, err := crypto.NewMasterKey()
	if err != nil {
		return err
	}
	fmt.Printf("REVPD_MASTER_KEY=%s\n", key)
	fmt.Fprintln(os.Stderr, "\nStore this in your .env and back it up. "+
		"Losing it means re-enrolling every second factor.")
	return nil
}

func cmdUserAdd(args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfigPath(), "path to config file")
	name := fs.String("u", "", "username")
	display := fs.String("name", "", "display name")
	admin := fs.Bool("admin", false, "grant the administrator role")
	hint := fs.String("hint", "", "name this account is matched by from the RDP client")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin instead of prompting")
	fs.Parse(args)

	if *name == "" {
		return errors.New("-u is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	db, log, _, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	var password string
	if *pwStdin {
		// Scripted setup: one line, no confirmation round.
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		password = cleanPipedLine(line)
	} else {
		password, err = readPassword("Password (at least 12 characters): ")
		if err != nil {
			return err
		}
		again, err := readPassword("Repeat: ")
		if err != nil {
			return err
		}
		if password != again {
			return errors.New("passwords do not match")
		}
	}

	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	role := "user"
	if *admin {
		role = "admin"
	}
	if *display == "" {
		*display = *name
	}
	if *hint == "" {
		*hint = *name
	}

	id, err := db.CreateUser(ctx, store.User{
		Username: *name, DisplayName: *display, PasswordHash: hash,
		Role: role, RDPHint: *hint,
	})
	if err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionUserCreated, Object: *name})
	fmt.Printf("Created %s (id %d, role %s).\nNow run:  revpd enroll -u %s\n", *name, id, role, *name)
	return nil
}

// cmdEnroll is the older spelling, kept because install.sh calls it.
func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	// Accepted and ignored: enrollUser resolves the config itself, and the
	// installer always passes the default path anyway.
	fs.String("c", defaultConfigPath(), "path to config file")
	name := fs.String("u", "", "username")
	fs.Parse(args)

	if *name == "" {
		return errors.New("-u is required")
	}

	return enrollUser(*name)
}

// enrollUser issues a fresh authenticator secret and a new set of backup
// codes. Shared by `revpd enroll`, `revpd user reset` and the menu, so all
// three behave identically.
func enrollUser(name string) error {
	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return err
	}
	ctx := context.Background()

	db, log, sealer, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := db.UserByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no such user %q", name)
	}

	secret, uri, err := mfa.TOTP{Skew: cfg.Auth.TOTPSkew}.Enroll("Revpd ("+cfg.Web.Hostname+")", u.Username)
	if err != nil {
		return err
	}

	enc, err := sealer.Seal(fmt.Sprintf("totp:%d", u.ID), []byte(secret))
	if err != nil {
		return err
	}
	if err := db.SetTOTPSecret(ctx, u.ID, enc); err != nil {
		return err
	}

	// Fresh codes, and the old ones stop working.
	if _, err := db.Exec(`DELETE FROM backup_codes WHERE user_id = ?`, u.ID); err != nil {
		return fmt.Errorf("clear old backup codes: %w", err)
	}

	codes := make([]string, 0, cfg.Auth.BackupCodes)
	for i := 0; i < cfg.Auth.BackupCodes; i++ {
		c, err := crypto.NewBackupCode()
		if err != nil {
			return err
		}
		h, err := crypto.HashPassword(crypto.NormalizeBackupCode(c))
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, u.ID, h); err != nil {
			return fmt.Errorf("store backup code: %w", err)
		}
		codes = append(codes, c)
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionEnrollTOTP, Object: u.Username})

	fmt.Printf("\nScan this with your authenticator app:\n\n  %s\n\n", uri)
	fmt.Printf("Or type the secret by hand:  %s\n\n", secret)
	fmt.Println("Backup codes — each works once, store them somewhere safe:")
	for _, c := range codes {
		fmt.Println("  " + c)
	}
	fmt.Println()
	return nil
}

func cmdTargetAdd(args []string) error {
	fs := flag.NewFlagSet("targetadd", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfigPath(), "path to config file")
	name := fs.String("name", "", "display name, e.g. \"Office PC\"")
	host := fs.String("host", "", "hostname (preferred over the IP for dialling)")
	ip := fs.String("ip", "", "IP address")
	mac := fs.String("mac", "", "MAC address for Wake-on-LAN")
	port := fs.Int("port", 3389, "RDP port")
	bcast := fs.String("broadcast", "255.255.255.255", "broadcast address for the magic packet")
	boot := fs.Int("boot", 120, "seconds to wait for the machine to come up")
	user := fs.String("for", "", "username to grant access to")
	fs.Parse(args)

	if *name == "" || (*ip == "" && *host == "") || *mac == "" {
		return errors.New("-name, -mac and either -ip or -host are required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	db, log, _, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	id, err := db.CreateTarget(ctx, store.Target{
		Name: *name, Hostname: *host, IP: *ip, RDPPort: *port,
		MAC: *mac, WoLBroadcast: *bcast, BootTimeoutS: *boot,
	})
	if err != nil {
		return err
	}

	if *user != "" {
		u, err := db.UserByName(ctx, *user)
		if err != nil {
			return fmt.Errorf("no such user %q", *user)
		}
		if err := db.GrantTargetAccess(ctx, u.ID, id); err != nil {
			return err
		}
		fmt.Printf("Created %q (id %d) and granted access to %s.\n", *name, id, *user)
	} else {
		fmt.Printf("Created %q (id %d). Grant access with -for USER or in the web UI.\n", *name, id)
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionTargetCreated, Object: *name})
	return nil
}

/* ---------------------------------------------------------------- audit --- */

func cmdAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: revpd audit verify [-c revpd.yaml]")
	}

	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfigPath(), "path to config file")
	fs.Parse(args[1:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	db, log, _, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	brk, n, err := log.Verify(ctx)
	if err != nil {
		return err
	}
	if brk != nil {
		fmt.Printf("audit chain BROKEN at entry %d: %s\n", brk.ID, brk.Reason)
		fmt.Printf("%d entries checked before the break\n", n)
		os.Exit(2)
	}

	fmt.Printf("audit chain intact — %d entries verified\n", n)
	fmt.Printf("head: %s\n", log.Head())
	return nil
}

/* ----------------------------------------------------------------- glue --- */

func defaultConfigPath() string {
	if p := os.Getenv("REVPD_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat("revpd.yaml"); err == nil {
		return "revpd.yaml"
	}
	return "/etc/revpd/revpd.yaml"
}

func openData(ctx context.Context, cfg config.Config) (*store.DB, *audit.Log, *crypto.Sealer, error) {
	key := cfg.MasterKey()
	if key == "" {
		// Almost always the secrets file could not be read, not that there is
		// no key. Saying "generate one" there would be terrible advice: a new
		// key makes the existing database unreadable.
		if err := config.EnvFileProblem(); err != nil {
			return nil, nil, nil, fmt.Errorf(
				"could not read the master key from %s: %w\n"+
					"The file is readable by root only. Run the command again with sudo.",
				config.EnvFilePath(defaultConfigPath()), err)
		}
		return nil, nil, nil, fmt.Errorf(
			"%s is not set, and %s does not contain it.\n"+
				"If this is a new installation, create the key with `revpd genkey`.\n"+
				"If it is not, the key is lost and the database cannot be decrypted — restore a backup.",
			cfg.Auth.MasterKeyEnv, config.EnvFilePath(defaultConfigPath()))
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, nil, nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := store.Open(ctx, filepath.Join(cfg.DataDir, "revpd.db"))
	if err != nil {
		return nil, nil, nil, err
	}

	log, err := audit.New(db.DB)
	if err != nil {
		db.Close()
		return nil, nil, nil, err
	}
	return db, log, sealer, nil
}

// stdin is shared across prompts: a bufio.Reader buffers ahead, so creating a
// new one per call would swallow the next line.
var stdin = bufio.NewReader(os.Stdin)

// readPassword reads from the terminal without echoing where it can, and falls
// back to a plain line read when stdin is a pipe (setup scripts, CI).
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if pw, err := readNoEcho(); err == nil {
		fmt.Fprintln(os.Stderr)
		return pw, nil
	}

	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password: %w", err)
	}
	return cleanPipedLine(line), nil
}

// cleanPipedLine strips what a shell adds around a piped password, and nothing
// else. A trailing space can be a legitimate part of a password; a byte-order
// mark cannot.
//
// Windows PowerShell prepends a UTF-8 BOM when piping into a native program,
// which silently becomes part of the password and makes the account
// unloggable-into with no visible cause. That is worth handling rather than
// leaving people to discover it.
func cleanPipedLine(s string) string {
	s = strings.TrimRight(s, "\r\n")
	return strings.TrimPrefix(s, "\uFEFF")
}

func setupLogging(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

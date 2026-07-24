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
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/web"
)

var version = "dev" // set with -ldflags at release time

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "revpd:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}

	switch os.Args[1] {
	case "serve":
		return cmdServe(os.Args[2:])
	case "genkey":
		return cmdGenKey()
	case "useradd":
		return cmdUserAdd(os.Args[2:])
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "targetadd":
		return cmdTargetAdd(os.Args[2:])
	case "audit":
		return cmdAudit(os.Args[2:])
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

  revpd genkey                       print a new master key for REVPD_MASTER_KEY
  revpd useradd  -u NAME [-admin]    create an account (prompts for a password)
  revpd enroll   -u NAME             set up the second factor, prints a QR URI
  revpd targetadd -name N -ip IP -mac MAC
  revpd serve    [-c revpd.yaml]     run the gateway
  revpd audit verify                 check the audit chain for tampering
  revpd version

Config is read from the file given with -c, then overridden by the
environment. See .env.example for the variables.
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

	// Web portal.
	apiSrv := api.New(db, log, cfg, authMgr, engine, sealer, web.Handler())
	httpSrv := &http.Server{
		Addr:              cfg.Web.Listen,
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
		// Certificates come from TLSConfig, so both arguments stay empty.
		err := httpSrv.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	go housekeeping(ctx, db, authMgr, cfg)

	slog.Info("revpd running",
		"version", version,
		"web", cfg.Web.Listen,
		"relay", cfg.Relay.Listen,
		"hostname", cfg.Web.Hostname,
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

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfigPath(), "path to config file")
	name := fs.String("u", "", "username")
	fs.Parse(args)

	if *name == "" {
		return errors.New("-u is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	db, log, sealer, err := openData(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := db.UserByName(ctx, *name)
	if err != nil {
		return fmt.Errorf("no such user %q", *name)
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
		return nil, nil, nil, fmt.Errorf(
			"%s is not set — generate one with `revpd genkey` and put it in your .env",
			cfg.Auth.MasterKeyEnv)
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

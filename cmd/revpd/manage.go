package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/backup"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/store"
)

/*
   Where the installer puts things. One place, so the menu, the backup and the
   uninstaller cannot drift apart from install.sh.
*/
const (
	installBinPath = "/usr/local/bin/revpd"
	installConfDir = "/etc/revpd"
	installDataDir = "/var/lib/revpd"
	installService = "/etc/systemd/system/revpd.service"
	installUnit    = "revpd"
	installUser    = "revpd"
)

/* ---------------------------------------------------------------- users --- */

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: revpd user add|list|rm|reset|lock|unlock")
	}

	switch args[0] {
	case "add":
		return userAdd(args[1:])
	case "list", "ls":
		return userList()
	case "rm", "remove", "delete":
		return userRemove(args[1:])
	case "reset":
		return userReset(args[1:])
	case "lock":
		return userSetStatus(args[1:], "locked")
	case "unlock":
		return userSetStatus(args[1:], "active")
	default:
		return fmt.Errorf("unknown: revpd user %s", args[0])
	}
}

// userAdd takes the name as a plain argument, so it reads the way people
// expect: revpd user add felix --admin
func userAdd(args []string) error {
	name, flags := splitName(args)
	if name == "" {
		return errors.New("usage: revpd user add NAME [--admin]")
	}

	role := "user"
	if has(flags, "--admin", "-admin") {
		role = "admin"
	}

	cfg, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()
	_ = cfg

	password, err := askNewPassword()
	if err != nil {
		return err
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	id, err := db.CreateUser(context.Background(), store.User{
		Username: name, DisplayName: name, PasswordHash: hash, Role: role, RDPHint: name,
	})
	if err != nil {
		return fmt.Errorf("could not create %s (does the name already exist?): %w", name, err)
	}

	log.Append(context.Background(), audit.Entry{Actor: "cli", Action: audit.ActionUserCreated, Object: name})

	okf("created %s (%s)", name, role)
	sayf("\nSet up their second factor now:\n  revpd user reset %s\n", name)
	_ = id
	return nil
}

func userList() error {
	_, db, _, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	users, err := db.ListUsers(context.Background())
	if err != nil {
		return err
	}
	if len(users) == 0 {
		sayf("No accounts yet. Create one with:  revpd user add NAME --admin\n")
		return nil
	}

	fmt.Printf("\n  %-20s %-8s %-10s %s\n", "USERNAME", "ROLE", "STATUS", "SECOND FACTOR")
	for _, u := range users {
		factor := "none"
		if len(u.TOTPSecretEnc) > 0 {
			factor = "authenticator"
		}
		if n, err := db.CountPasskeys(context.Background(), u.ID); err == nil && n > 0 {
			if factor == "none" {
				factor = fmt.Sprintf("%d passkey(s)", n)
			} else {
				factor += fmt.Sprintf(" + %d passkey(s)", n)
			}
		}
		fmt.Printf("  %-20s %-8s %-10s %s\n", u.Username, u.Role, u.Status, factor)
	}
	fmt.Println()
	return nil
}

func userRemove(args []string) error {
	name, flags := splitName(args)
	if name == "" {
		return errors.New("usage: revpd user rm NAME")
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	u, err := db.UserByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no such user %q", name)
	}

	if !has(flags, "--yes", "-y") {
		sayf("\nThis removes %s along with their passkeys, backup codes and access.\n", name)
		if !confirm("Remove " + name + "?") {
			sayf("Nothing was changed.\n")
			return nil
		}
	}

	if err := db.DeleteUser(ctx, u.ID); err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionUserDeleted, Object: name})
	okf("removed %s", name)
	return nil
}

// userReset issues a new authenticator secret and a fresh set of backup codes.
func userReset(args []string) error {
	name, _ := splitName(args)
	if name == "" {
		return errors.New("usage: revpd user reset NAME")
	}
	return enrollUser(name)
}

func userSetStatus(args []string, status string) error {
	name, _ := splitName(args)
	if name == "" {
		return fmt.Errorf("usage: revpd user %s NAME", map[string]string{"locked": "lock", "active": "unlock"}[status])
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	u, err := db.UserByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no such user %q", name)
	}
	if err := db.SetUserStatus(ctx, u.ID, status); err != nil {
		return err
	}

	// Locking has to bite now, not when the session happens to expire.
	if status != "active" {
		db.RevokeGrantsForUser(ctx, u.ID)
	}

	log.Append(ctx, audit.Entry{
		Actor: "cli", Action: audit.ActionUserUpdated, Object: name,
		Detail: map[string]any{"status": status},
	})

	if status == "active" {
		okf("%s can sign in again", name)
	} else {
		okf("%s is locked out", name)
	}
	return nil
}

/* -------------------------------------------------------------- targets --- */

func cmdTarget(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: revpd target add|list|rm")
	}

	switch args[0] {
	case "add":
		return targetAdd(args[1:])
	case "list", "ls":
		return targetList()
	case "rm", "remove", "delete":
		return targetRemove(args[1:])
	default:
		return fmt.Errorf("unknown: revpd target %s", args[0])
	}
}

// targetAdd reads as a sentence: revpd target add "Office PC" 192.168.1.40 aa:bb:cc:dd:ee:ff
func targetAdd(args []string) error {
	var positional []string
	var flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			continue
		}
		positional = append(positional, a)
	}

	if len(positional) < 3 {
		return errors.New("usage: revpd target add NAME IP MAC [--for USER]")
	}
	name, ip, mac := positional[0], positional[1], positional[2]

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	id, err := db.CreateTarget(ctx, store.Target{Name: name, IP: ip, MAC: mac})
	if err != nil {
		return fmt.Errorf("could not create %q (does the name already exist?): %w", name, err)
	}

	// --for USER, or the remaining positional argument after the three above.
	grantTo := valueOf(args, "--for", "-for")
	if grantTo == "" && len(positional) > 3 {
		grantTo = positional[3]
	}

	if grantTo != "" {
		u, err := db.UserByName(ctx, grantTo)
		if err != nil {
			return fmt.Errorf("target created, but there is no user %q to grant it to", grantTo)
		}
		if err := db.GrantTargetAccess(ctx, u.ID, id); err != nil {
			return err
		}
		okf("added %q and gave %s access", name, grantTo)
	} else {
		okf("added %q", name)
		sayf("\nGive someone access:  revpd target add … --for USER\n" +
			"or do it in the web interface.\n")
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionTargetCreated, Object: name})
	_ = flags
	return nil
}

func targetList() error {
	_, db, _, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	targets, err := db.ListTargets(context.Background())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		sayf("No machines yet. Add one with:\n  revpd target add \"Office PC\" 192.168.1.40 aa:bb:cc:dd:ee:ff\n")
		return nil
	}

	fmt.Printf("\n  %-24s %-22s %s\n", "NAME", "ADDRESS", "MAC")
	for _, t := range targets {
		fmt.Printf("  %-24s %-22s %s\n", t.Name, t.Addr(), t.MAC)
	}
	fmt.Println()
	return nil
}

func targetRemove(args []string) error {
	name, flags := splitName(args)
	if name == "" {
		return errors.New("usage: revpd target rm NAME")
	}

	_, db, log, _, err := open()
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	t, err := db.TargetByName(ctx, name)
	if err != nil {
		return fmt.Errorf("no such machine %q", name)
	}

	if !has(flags, "--yes", "-y") && !confirm("Remove "+name+"?") {
		sayf("Nothing was changed.\n")
		return nil
	}

	if err := db.DeleteTarget(ctx, t.ID); err != nil {
		return err
	}

	log.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionTargetDeleted, Object: name})
	okf("removed %q", name)
	return nil
}

/* -------------------------------------------------------------- service --- */

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: revpd service start|stop|restart|status")
	}

	action := args[0]
	switch action {
	case "start", "stop", "restart", "status":
	default:
		return fmt.Errorf("unknown: revpd service %s", action)
	}

	if err := requireLinux(); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", action, installUnit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// systemctl status exits non-zero when the unit is stopped, which is
		// information rather than a failure.
		if action == "status" {
			return nil
		}
		return fmt.Errorf("systemctl %s failed (try sudo): %w", action, err)
	}

	if action != "status" {
		okf("service %sed", strings.TrimSuffix(action, "e"))
	}
	return nil
}

func cmdLogs(args []string) error {
	if err := requireLinux(); err != nil {
		return err
	}

	journalArgs := []string{"-u", installUnit, "-n", "50", "--no-pager"}
	if has(args, "-f", "--follow") {
		journalArgs = []string{"-u", installUnit, "-f"}
	}

	cmd := exec.Command("journalctl", journalArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// cmdStatus is the overview the menu shows at the top, also usable on its own.
func cmdStatus() error {
	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		sayf("\n  Not configured yet — no %s\n\n", defaultConfigPath())
		return nil
	}

	state := serviceState()

	fmt.Println()
	fmt.Printf("  Service    %s\n", state)
	fmt.Printf("  Address    %s\n", cfg.Web.Hostname)
	fmt.Printf("  RDP        %s\n", cfg.Relay.Listen)
	fmt.Printf("  Web        %s\n", cfg.Web.Listen)

	// The counts need the database, which needs the master key. Missing it is
	// worth saying plainly rather than failing the whole command.
	if db, _, _, err := openWith(cfg); err == nil {
		defer db.Close()
		ctx := context.Background()

		users, _ := db.ListUsers(ctx)
		targets, _ := db.ListTargets(ctx)
		fmt.Printf("  Accounts   %d\n", len(users))
		fmt.Printf("  Machines   %d\n", len(targets))
	} else {
		fmt.Printf("  Database   unavailable (%v)\n", err)
	}
	fmt.Println()
	return nil
}

// serviceState is a word, not a systemctl dump.
func serviceState() string {
	if runtime.GOOS != "linux" {
		return "not managed on this platform"
	}

	out, err := exec.Command("systemctl", "is-active", installUnit).Output()
	state := strings.TrimSpace(string(out))

	switch {
	case state == "active":
		return "running"
	case state == "inactive":
		return "stopped"
	case state == "failed":
		return "failed — see: revpd logs"
	case err != nil && state == "":
		return "not installed"
	default:
		return state
	}
}

/* -------------------------------------------------------------- backups --- */

func cmdBackup(args []string) error {
	path, _ := splitName(args)

	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return err
	}

	if path == "" {
		path = defaultBackupPath()
		if isInteractive() {
			path = askPath("Save backup to", path)
		}
	}
	path = expandPath(path)

	// A directory means "put it in here with the usual name".
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, filepath.Base(defaultBackupPath()))
	}

	if _, err := os.Stat(path); err == nil {
		if !confirm(fmt.Sprintf("%s already exists. Overwrite?", path)) {
			sayf("Nothing was written.\n")
			return nil
		}
	}

	passphrase, err := askNewPassphrase()
	if err != nil {
		return err
	}

	db, _, _, err := openWith(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	step("Backing up")

	// A consistent snapshot, not a copy of a live file.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".revpd-snapshot-*")
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}
	snapshot := tmp.Name()
	tmp.Close()
	os.Remove(snapshot) // VACUUM INTO needs the path to be free
	defer os.Remove(snapshot)

	if err := db.BackupTo(context.Background(), snapshot); err != nil {
		return err
	}

	dbBytes, err := os.ReadFile(snapshot)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	okf("database (%s)", humanSize(len(dbBytes)))

	// The env file holds the master key. Without it the database is unreadable
	// on another machine, so a backup that skipped it would be useless.
	envBytes, err := os.ReadFile(filepath.Join(installConfDir, ".env"))
	if err != nil {
		warnf("could not read %s/.env — the backup will not include the master key", installConfDir)
		warnf("restoring it elsewhere will need that key supplied by hand")
	} else {
		okf("master key")
	}

	configBytes, _ := os.ReadFile(defaultConfigPath())

	host, _ := os.Hostname()
	err = backup.WriteFile(path, backup.Contents{
		Database: dbBytes,
		Env:      envBytes,
		Config:   configBytes,
		Created:  time.Now(),
		Hostname: host,
		Version:  version,
	}, passphrase)
	if err != nil {
		return err
	}

	info, _ := os.Stat(path)
	okf("wrote %s (%s)", path, humanSize(int(info.Size())))

	sayf("\nKeep this somewhere safe — it contains the key to every enrolled\n"+
		"second factor. To move it to another machine:\n\n"+
		"  scp %s user@other-host:\n"+
		"  ssh user@other-host  sudo revpd restore %s\n\n",
		path, filepath.Base(path))
	return nil
}

func cmdRestore(args []string) error {
	path, flags := splitName(args)

	if path == "" {
		if !isInteractive() {
			return errors.New("usage: revpd restore FILE" + backup.Extension)
		}
		path = askPath("Restore from", findNewestBackup())
	}
	path = expandPath(path)

	// Recognise the file before asking for a passphrase, so pointing at the
	// wrong file costs one line rather than a failed decryption.
	created, err := backup.PeekFile(path)
	if err != nil {
		return err
	}
	sayf("\n  Backup from %s\n", created.Local().Format("2 January 2006, 15:04"))

	if !has(flags, "--yes", "-y") {
		sayf("\nRestoring replaces the current database, master key and configuration.\n")
		if !confirm("Continue?") {
			sayf("Nothing was changed.\n")
			return nil
		}
	}

	passphrase, err := readPassword("  Passphrase: ")
	if err != nil {
		return err
	}

	c, err := backup.ReadFile(path, passphrase)
	if err != nil {
		return err
	}
	okf("unlocked")

	if err := requireRoot(); err != nil {
		return err
	}

	// Stop the service so nothing writes while files are swapped underneath.
	wasRunning := serviceState() == "running"
	if wasRunning {
		exec.Command("systemctl", "stop", installUnit).Run()
		okf("stopped the service")
	}

	cfg, cfgErr := config.Load(defaultConfigPath())
	dataDir := installDataDir
	if cfgErr == nil && cfg.DataDir != "" {
		dataDir = cfg.DataDir
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dataDir, err)
	}
	if err := os.MkdirAll(installConfDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", installConfDir, err)
	}

	// Remove the WAL sidecars: leaving them next to a replaced database would
	// mix old journal state into new data.
	dbPath := filepath.Join(dataDir, "revpd.db")
	for _, sidecar := range []string{dbPath + "-wal", dbPath + "-shm"} {
		os.Remove(sidecar)
	}

	if err := os.WriteFile(dbPath, c.Database, 0o600); err != nil {
		return fmt.Errorf("restore database: %w", err)
	}
	okf("database")

	if len(c.Env) > 0 {
		if err := os.WriteFile(filepath.Join(installConfDir, ".env"), c.Env, 0o640); err != nil {
			return fmt.Errorf("restore master key: %w", err)
		}
		okf("master key")
	}
	if len(c.Config) > 0 {
		if err := os.WriteFile(defaultConfigPath(), c.Config, 0o640); err != nil {
			return fmt.Errorf("restore configuration: %w", err)
		}
		okf("configuration")
	}

	// Ownership, or the service cannot read what it just got back.
	if runtime.GOOS == "linux" {
		exec.Command("chown", "-R", installUser+":"+installUser, dataDir).Run()
		exec.Command("chown", "root:"+installUser, filepath.Join(installConfDir, ".env")).Run()
		exec.Command("chown", "root:"+installUser, defaultConfigPath()).Run()
	}

	if wasRunning {
		if err := exec.Command("systemctl", "start", installUnit).Run(); err != nil {
			warnf("could not start the service: %v", err)
		} else {
			okf("started the service")
		}
	}

	sayf("\n  Restored. Check the audit trail survived:\n    revpd audit verify\n\n")
	return nil
}

func defaultBackupPath() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "revpd"
	}
	name := fmt.Sprintf("revpd-%s-%s%s", host, time.Now().Format("2006-01-02"), backup.Extension)

	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, name)
	}
	return name
}

// findNewestBackup suggests something sensible when restore is run with no
// argument, so the common case is one keypress.
func findNewestBackup() string {
	dirs := []string{"."}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, home)
	}

	var newest string
	var newestTime time.Time

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), backup.Extension) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(newestTime) {
				newestTime = info.ModTime()
				newest = filepath.Join(dir, e.Name())
			}
		}
	}
	return newest
}

/* ------------------------------------------------------------ uninstall --- */

// removalStep is one thing the uninstaller will do. Building the list before
// touching anything makes it printable, testable and hard to get wrong.
type removalStep struct {
	Description string
	Path        string   // a file or directory to delete
	Command     []string // or a command to run
}

// uninstallPlan lists everything the installer created.
//
// A pure function on purpose: the guard against deleting "" or "/" is the kind
// of thing that has to be tested, and a test must never actually delete.
func uninstallPlan(dataDir string, keepData bool) ([]removalStep, error) {
	if dataDir == "" {
		dataDir = installDataDir
	}

	steps := []removalStep{
		{Description: "stop the service", Command: []string{"systemctl", "stop", installUnit}},
		{Description: "disable the service", Command: []string{"systemctl", "disable", installUnit}},
		{Description: "remove the service definition", Path: installService},
		{Description: "reload systemd", Command: []string{"systemctl", "daemon-reload"}},
		{Description: "clear any failed state", Command: []string{"systemctl", "reset-failed", installUnit}},
	}

	if !keepData {
		steps = append(steps,
			removalStep{Description: "delete the database and all accounts", Path: dataDir},
			removalStep{Description: "delete the master key and configuration", Path: installConfDir},
		)
	}

	steps = append(steps,
		removalStep{Description: "remove the system account", Command: []string{"userdel", installUser}},
		// Last: on Linux a running binary can delete itself, but doing it
		// earlier would strand the steps that follow.
		removalStep{Description: "remove the program", Path: installBinPath},
	)

	// Nothing may ever point at the root of the filesystem or nowhere.
	for _, s := range steps {
		if s.Path == "" {
			continue
		}
		if !safeToRemove(s.Path) {
			return nil, fmt.Errorf("refusing to remove %q — this is a bug, nothing was deleted", s.Path)
		}
	}
	return steps, nil
}

// safeToRemove rejects anything that is not a specific absolute unix path.
//
// Deliberately not filepath.IsAbs: that follows the rules of whatever platform
// the binary was compiled on, and on Windows it would call "/etc/revpd"
// relative. These paths are always unix paths, whoever built the binary.
func safeToRemove(p string) bool {
	clean := path.Clean(strings.ReplaceAll(p, "\\", "/"))

	if !strings.HasPrefix(clean, "/") {
		return false // relative — never
	}
	if clean == "/" || clean == "." || clean == ".." {
		return false
	}
	if strings.Contains(clean, "..") {
		return false // no escaping upward
	}

	// A single top-level component would mean /etc, /usr, /var and the like.
	// Every real path here is at least two deep.
	if strings.Count(strings.TrimSuffix(clean, "/"), "/") < 2 {
		return false
	}
	return true
}

func cmdUninstall(args []string) error {
	keepData := has(args, "--keep-data", "-keep-data")
	assumeYes := has(args, "--yes", "-y")

	if err := requireLinux(); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}

	dataDir := installDataDir
	if cfg, err := config.Load(defaultConfigPath()); err == nil && cfg.DataDir != "" {
		dataDir = cfg.DataDir
	}

	steps, err := uninstallPlan(dataDir, keepData)
	if err != nil {
		return err
	}

	sayf("\n  This removes Revpd from this machine:\n\n")
	for _, s := range steps {
		if s.Path != "" {
			sayf("    %s\n", s.Path)
		}
	}
	sayf("    the %s service and system account\n", installUnit)

	if keepData {
		sayf("\n  %s and %s are kept.\n", dataDir, installConfDir)
	} else {
		sayf("\n  %sThis cannot be undone.%s Every account, the audit trail and the\n", bold, reset)
		sayf("  master key are deleted. Take a backup first if you might want it:\n")
		sayf("    revpd backup\n")
	}

	if !assumeYes {
		sayf("\n")
		if !confirmTyped("Type 'yes' to remove Revpd: ", "yes") {
			sayf("\nNothing was removed.\n")
			return nil
		}
	}

	sayf("\n")
	var failures []string

	for _, s := range steps {
		switch {
		case s.Path != "":
			if err := os.RemoveAll(s.Path); err != nil && !os.IsNotExist(err) {
				failures = append(failures, fmt.Sprintf("%s: %v", s.Path, err))
				continue
			}
		case len(s.Command) > 0:
			// Best effort: a service that was already stopped is not a failure.
			exec.Command(s.Command[0], s.Command[1:]...).Run()
		}
		okf("%s", s.Description)
	}

	if len(failures) > 0 {
		sayf("\n  Some things could not be removed:\n")
		for _, f := range failures {
			sayf("    %s\n", f)
		}
		return errors.New("uninstall finished with problems")
	}

	sayf("\n  %sRevpd has been removed.%s\n\n", bold, reset)
	return nil
}

/* ----------------------------------------------------------------- glue --- */

// open loads the config and the database in one step, which every management
// command needs and nothing else should have to repeat.
func open() (config.Config, *store.DB, *audit.Log, *crypto.Sealer, error) {
	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return cfg, nil, nil, nil, err
	}
	db, log, sealer, err := openData(context.Background(), cfg)
	return cfg, db, log, sealer, err
}

func openWith(cfg config.Config) (*store.DB, *audit.Log, *crypto.Sealer, error) {
	return openData(context.Background(), cfg)
}

// lookPath is exec.LookPath, wrapped so callers here read the same way.
func lookPath(name string) (string, error) { return exec.LookPath(name) }

// runInteractive hands the terminal to another program — an editor, or
// journalctl following a log — and waits for it.
func runInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func requireLinux() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this only works on the Linux machine where Revpd is installed (this is %s)", runtime.GOOS)
	}
	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root — run it again with sudo")
	}
	return nil
}

// splitName separates the first non-flag argument from the flags, so callers
// can write `revpd user add felix --admin` in any order.
func splitName(args []string) (name string, flags []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			continue
		}
		if name == "" {
			name = a
		}
	}
	return name, flags
}

func has(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

func valueOf(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, n+"=") {
				return strings.TrimPrefix(a, n+"=")
			}
		}
	}
	return ""
}

func humanSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.0f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

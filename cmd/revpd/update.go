package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/update"
)

/*
	The command-line half of updating.

	`revpd update` and `revpd update install` are for a person at a terminal.
	`revpd update apply-staged` is not: systemd runs it as root when the web
	interface asks for an update, because the service itself is sandboxed away
	from /usr and cannot replace its own binary.
*/

func cmdUpdate(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "", "check":
		return updateCheck()
	case "install", "apply":
		return updateInstall(args[1:])
	case "apply-staged":
		return updateApplyStaged()
	case "rollback":
		return updateRollback()
	default:
		return fmt.Errorf("unknown command `revpd update %s` — try check, install or rollback", sub)
	}
}

func updateManager() (*update.Manager, config.Config, error) {
	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return nil, cfg, err
	}
	m, err := update.NewManager(update.Options{
		DataDir: cfg.DataDir,
		Version: version,
		Repo:    cfg.Update.Repo,
	})
	return m, cfg, err
}

/* ---------------------------------------------------------------- check --- */

func updateCheck() error {
	m, cfg, err := updateManager()
	if err != nil {
		return err
	}

	fmt.Printf("Running:  revpd %s\n", version)
	fmt.Printf("Releases: %s\n\n", m.Repo())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	avail, err := m.Check(ctx, cfg.Update.Prerelease)
	if err != nil {
		return err
	}
	if avail == nil {
		fmt.Println("This is the latest release.")
		return nil
	}

	fmt.Printf("%s is available.\n", avail.Version)
	if !avail.PublishedAt.IsZero() {
		fmt.Printf("Published %s\n", avail.PublishedAt.Local().Format("2 January 2006"))
	}
	if avail.URL != "" {
		fmt.Printf("%s\n", avail.URL)
	}
	if notes := strings.TrimSpace(avail.Notes); notes != "" {
		fmt.Printf("\n%s\n", indent(firstLines(notes, 12), "  "))
	}
	fmt.Printf("\nInstall it with:  sudo revpd update install\n")
	return nil
}

/* -------------------------------------------------------------- install --- */

func updateInstall(args []string) error {
	if err := requireLinux(); err != nil {
		return err
	}

	m, cfg, err := updateManager()
	if err != nil {
		return err
	}

	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	if target == "" {
		fmt.Println("Checking for a newer release…")
		avail, err := m.Check(ctx, cfg.Update.Prerelease)
		if err != nil {
			return err
		}
		if avail == nil {
			fmt.Printf("Already running the latest release (%s). Nothing to do.\n", version)
			return nil
		}
		target = avail.Version
	}

	// Downloading needs no privileges; installing does. Checking now means the
	// answer arrives before the download rather than after it.
	root := os.Geteuid() == 0
	if !root && !update.ApplierInstalled() {
		return fmt.Errorf(
			"installing %s needs root, and the background updater is not installed either.\nRun it again with sudo:  sudo revpd update install", target)
	}

	fmt.Printf("Downloading %s…\n", target)
	staged, err := m.Stage(ctx, target, cliActor(), false)
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s (sha256 %s…)\n", staged.Version, staged.SHA256[:12])

	if !root {
		// The privileged unit is installed, so hand it over and let systemd
		// do the part this process is not allowed to.
		if err := m.RequestApply(cliActor()); err != nil {
			return err
		}
		fmt.Println("Handed to the background updater. Watch it with:  journalctl -u revpd-update -f")
		return nil
	}

	if err := m.RequestApply(cliActor()); err != nil {
		return err
	}
	return applyStaged(m.Dir(), true)
}

/* --------------------------------------------------------- apply-staged --- */

// updateApplyStaged is what systemd runs. It is deliberately not in the help
// text: it is a mechanism, not a command anyone needs to type.
func updateApplyStaged() error {
	if os.Geteuid() != 0 {
		return errors.New("`revpd update apply-staged` replaces the installed binary and must run as root")
	}

	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return err
	}
	return applyStaged(filepath.Join(cfg.DataDir, "update"), false)
}

func applyStaged(dir string, verbose bool) error {
	log := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	}

	res, err := update.Apply(context.Background(), update.ApplyOptions{
		Dir:  dir,
		Unit: installUnit,
		Logf: log,
	})

	if errors.Is(err, update.ErrNoRequest) {
		if verbose {
			fmt.Println("Nothing is waiting to be installed.")
		}
		return nil
	}
	if res == nil {
		return err
	}

	if res.OK {
		fmt.Printf("\n%s\n", res.Message)
		return nil
	}

	// The message already says what happened and what state the machine is in.
	return errors.New(res.Message)
}

/* ------------------------------------------------------------- rollback --- */

func updateRollback() error {
	if err := requireRoot(); err != nil {
		return err
	}

	cfg, err := config.Load(defaultConfigPath())
	if err != nil {
		return err
	}

	dir := filepath.Join(cfg.DataDir, "update", "rollback")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("there is no previous version to go back to — %s is empty", dir)
	}

	// The most recently kept backup is the version that was running before the
	// last update.
	newest, newestAt := "", time.Time{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newestAt) {
			newest, newestAt = filepath.Join(dir, e.Name()), info.ModTime()
		}
	}
	if newest == "" {
		return fmt.Errorf("no usable backup in %s", dir)
	}

	fmt.Printf("Going back to %s (kept %s).\n",
		strings.TrimPrefix(filepath.Base(newest), "revpd-"), newestAt.Local().Format("2 Jan 15:04"))

	res, err := update.Restore(context.Background(), update.ApplyOptions{
		Dir:  filepath.Join(cfg.DataDir, "update"),
		Unit: installUnit,
		Logf: func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	}, newest)
	if err != nil && res == nil {
		return err
	}
	fmt.Println(res.Message)
	if !res.OK {
		return errors.New("the rollback did not complete")
	}
	return nil
}

/* ---------------------------------------------------------------- utils --- */

func cliActor() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u + " (cli)"
	}
	return "cli"
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + "\n…"
}

func indent(s, with string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = with + l
	}
	return strings.Join(lines, "\n")
}

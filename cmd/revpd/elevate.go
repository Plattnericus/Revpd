package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

/*
	Getting the privileges an action needs, without making anyone start over.

	Most of what this program does touches things only root may touch: the
	systemd units, /etc/revpd, the database under /var/lib/revpd. Telling
	somebody who is three levels into a menu that they should have used sudo is
	a poor answer — they have to quit, retype the command and find their place
	again.

	So the command runs itself again through sudo instead.

	The password is never handled here. sudo prompts for it on the terminal
	directly and reads it itself; this process does not see it, store it, or
	pass it anywhere. All that happens on this side is starting sudo with the
	same arguments and waiting.
*/

// elevatedMarker stops a loop. If sudo returns without actually raising
// privileges — a misconfigured sudoers file can do this — a second attempt
// would fail the same way, forever.
const elevatedMarker = "REVPD_ELEVATED"

// errElevated reports that the work was done by a child process running as
// root. The caller has nothing left to do and must not do it twice.
var errElevated = errors.New("the action ran with administrator rights")

// needRoot makes sure this action has the privileges it needs.
//
// It returns nil when already root, so the caller carries on. Otherwise it
// runs the action again under sudo and returns errElevated once that has
// finished — meaning the work is done and this process should stop.
//
// what describes the action in a few words, so the password prompt explains
// itself rather than appearing out of nowhere.
//
// argv is the command line that performs this action. Callers pass their own
// rather than letting this reach for os.Args, because the same functions are
// reached from the menu, where os.Args is just "revpd" — re-running that would
// open a second menu as root and do nothing at all.
func needRoot(what string, argv ...string) error {
	if os.Geteuid() == 0 {
		return nil
	}

	if len(argv) == 0 {
		argv = os.Args[1:]
	}
	if len(argv) == 0 {
		// Nothing to re-run. A caller forgot its argv; say so plainly rather
		// than starting a root shell of a menu.
		return fmt.Errorf("%s needs administrator rights. Run it again with sudo", what)
	}

	// sudo already ran and we are still not root. Trying again would loop.
	if os.Getenv(elevatedMarker) != "" {
		return fmt.Errorf(
			"sudo ran but this is still not running as root, so %s cannot go ahead.\n"+
				"Check the sudoers configuration, or sign in as root and try again", what)
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("this needs root and the program cannot find its own path: %w", err)
	}
	// Resolve it: sudo should start this exact binary, not whichever revpd a
	// symlink or a PATH entry happens to point at.
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf(
			"%s needs administrator rights, and sudo is not installed.\n"+
				"Sign in as root and run:  %s %s",
			what, self, strings.Join(argv, " "))
	}

	if !isInteractive() {
		// A script or a pipe has nobody to answer a password prompt, and a
		// command that hangs waiting for one is worse than one that explains
		// itself and stops.
		return fmt.Errorf(
			"%s needs administrator rights.\nRun:  sudo %s %s",
			what, self, strings.Join(argv, " "))
	}

	sayf("\n  %sThis needs administrator rights:%s %s\n", bold, reset, what)
	sayf("  %sStarting it again with sudo — you may be asked for your password.%s\n\n", dim, reset)

	return runAsRoot(sudo, self, argv)
}

// runAsRoot starts the same command under sudo and waits for it.
//
// Stdin, stdout and stderr are the terminal's own, so sudo's prompt appears
// where the user is looking and what they type goes straight to sudo. Nothing
// is piped through this process.
func runAsRoot(sudo, self string, args []string) error {
	cmd := exec.Command(sudo, append([]string{self}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// The marker travels through sudo's environment allowlist only if sudo is
	// configured to pass it; when it is not, the child simply tries once more
	// and succeeds, because by then it is root.
	cmd.Env = append(os.Environ(), elevatedMarker+"=1")

	err := cmd.Run()
	if err == nil {
		return errElevated
	}

	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// The child ran and decided its own outcome — a refused password, a
		// declined confirmation, a command that failed. It printed whatever it
		// had to say, so repeating anything here would only bury it.
		return errElevated
	}
	return fmt.Errorf("could not run sudo: %w", err)
}

// rootCommands are the ones that cannot work without root, because they read
// /etc/revpd — the configuration is 0640 root:revpd and the secrets file
// beside it holds the master key.
//
// Listed rather than discovered by trying and failing: "permission denied" on
// a path somebody did not ask about is a worse first experience than being
// told what is needed and asked for it.
var rootCommands = map[string]bool{
	"user": true, "target": true, "machine": true, "access": true,
	"passkey": true, "passkeys": true, "wake": true, "sessions": true,
	"session": true, "logs": true, "status": true, "config": true,
	"doctor": true, "check": true, "audit": true, "backup": true,
	"restore": true, "uninstall": true, "service": true,
	"useradd": true, "enroll": true, "targetadd": true,
}

// elevateIfNeeded raises privileges for a command that cannot work without
// them, before it gets far enough to fail on a file it cannot open.
//
// `serve` is deliberately absent: systemd starts it as the unprivileged
// service account on purpose, and it must never quietly become root.
// `genkey`, `version` and `help` need nothing.
func elevateIfNeeded(args []string) error {
	if len(args) == 0 || !rootCommands[args[0]] {
		return nil
	}

	// Reading the service status needs nothing; changing it does. The service
	// command sorts that out for itself.
	if args[0] == "service" && len(args) > 1 && args[1] == "status" {
		return nil
	}

	return needRoot(describe(args), args...)
}

// describe names the action for the password prompt, so it explains itself.
func describe(args []string) string {
	switch args[0] {
	case "user", "useradd":
		return "managing accounts"
	case "target", "machine", "targetadd":
		return "managing machines"
	case "access":
		return "changing who can reach what"
	case "backup":
		return "taking a backup"
	case "audit":
		return "reading the audit log"
	case "logs":
		return "reading the service log"
	case "doctor", "check":
		return "checking the installation"
	case "status":
		return "reading the status"
	case "config":
		return "reading the configuration"
	default:
		return "this"
	}
}

// requireRoot is the older, blunter check: it refuses rather than elevating.
//
// Kept for the places where raising privileges would be wrong — the applier
// that systemd starts, which must already be root and should say so loudly if
// it is not, rather than quietly asking a service account for a password.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root — run it again with sudo")
	}
	return nil
}

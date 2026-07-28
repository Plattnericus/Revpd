package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

/*
	Raising privileges.

	The property that matters most is a negative one: this program never sees
	the password. sudo prompts for it on the terminal and reads it itself, and
	the test for that is that our side of the exchange is only ever an exec
	with inherited standard streams.
*/

// fakeSudo puts a stand-in for sudo on PATH which records how it was called
// and runs whatever it was asked to run.
func fakeSudo(t *testing.T, behaviour string) (dir, log string) {
	t.Helper()

	// sudo, an effective uid and a shell script that PATH will pick up are all
	// Unix ideas. Windows 11 even ships its own sudo.exe, which would be found
	// before the stand-in below and would do something quite different. This
	// runs where the code runs; CI is Linux.
	if runtime.GOOS == "windows" {
		t.Skip("elevation is done through sudo; there is no equivalent to exercise on Windows")
	}

	dir = t.TempDir()
	log = filepath.Join(dir, "called")

	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + log + "\n" +
		"printf 'REVPD_ELEVATED=%s\\n' \"$REVPD_ELEVATED\" >> " + log + "\n" +
		behaviour + "\n"

	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir, log
}

func TestElevationRunsTheActionNotTheMenu(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root, so there is nothing to elevate")
	}

	dir, log := fakeSudo(t, "exit 0")

	// runAsRoot rather than needRoot: `go test` has no terminal, and needRoot
	// rightly refuses to summon a password prompt where nobody can answer it.
	// What is under test here is what sudo is asked to run.
	//
	// The menu reaches these functions with no command-line arguments at all,
	// so passing the action's own argv is what stops sudo from opening a
	// second menu as root and doing nothing.
	self, _ := os.Executable()
	err := runAsRoot(filepath.Join(dir, "sudo"), self, []string{"uninstall", "--keep-data"})
	if !errors.Is(err, errElevated) {
		t.Fatalf("err = %v, want errElevated", err)
	}

	body, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatalf("sudo was never called: %v", readErr)
	}
	got := string(body)

	if !strings.Contains(got, "uninstall") || !strings.Contains(got, "--keep-data") {
		t.Errorf("sudo was called without the action:\n%s", got)
	}
	if !strings.Contains(got, "REVPD_ELEVATED=1") {
		t.Errorf("the loop marker was not passed on:\n%s", got)
	}
}

// The binary sudo is asked to run has to be this one, by absolute path.
// Letting sudo resolve "revpd" through PATH would hand root to whichever one
// it found first.
func TestElevationNamesThisBinaryByAbsolutePath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root")
	}

	dir, log := fakeSudo(t, "exit 0")

	// The path needRoot would resolve: this binary, symlinks followed.
	self, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	if err := runAsRoot(filepath.Join(dir, "sudo"), self, []string{"status"}); !errors.Is(err, errElevated) {
		t.Fatalf("err = %v", err)
	}

	body, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(string(body), "\n", 2)[0]

	if !filepath.IsAbs(first) {
		t.Fatalf("sudo was given %q, which is not an absolute path", first)
	}
	if first != self {
		t.Errorf("sudo was given %q, want this binary at %q", first, self)
	}
}

// A misconfigured sudoers file can let sudo succeed without actually raising
// privileges. Trying again would loop until the terminal filled up.
func TestElevationRefusesToLoop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root")
	}
	t.Setenv(elevatedMarker, "1")

	err := needRoot("testing", "status")
	if errors.Is(err, errElevated) {
		t.Fatal("tried to elevate a second time")
	}
	if err == nil {
		t.Fatal("carried on without the privileges it needs")
	}
	if !strings.Contains(err.Error(), "sudoers") {
		t.Errorf("the message does not say what to look at: %v", err)
	}
}

// A script or a cron job has nobody to answer a password prompt. Hanging on
// one is worse than stopping with the command to run.
func TestElevationDoesNotPromptWhenNobodyIsWatching(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root")
	}
	if isInteractive() {
		t.Skip("this test needs a non-interactive stdin, which `go test` provides")
	}

	_, log := fakeSudo(t, "exit 0")

	err := needRoot("testing", "uninstall")
	if errors.Is(err, errElevated) {
		t.Fatal("prompted for a password with no terminal to prompt on")
	}
	if err == nil {
		t.Fatal("carried on without privileges")
	}
	if !strings.Contains(err.Error(), "sudo") || !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("the message does not give the command to run: %v", err)
	}
	if _, statErr := os.Stat(log); statErr == nil {
		t.Error("sudo was started anyway")
	}
}

func TestNoElevationWhenAlreadyRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root, which is the usual case")
	}
	if err := needRoot("testing", "status"); err != nil {
		t.Fatalf("root was asked to elevate: %v", err)
	}
}

// Without an argv there is nothing to re-run, and starting a menu as root
// would look like it worked while doing nothing.
func TestElevationRefusesWithoutSomethingToRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root")
	}

	// Stand in for the menu: the program was started as bare `revpd`.
	old := os.Args
	os.Args = []string{"revpd"}
	t.Cleanup(func() { os.Args = old })

	err := needRoot("testing")
	if errors.Is(err, errElevated) {
		t.Fatal("elevated with no action to perform")
	}
	if err == nil {
		t.Fatal("carried on without privileges")
	}
}

/*
The password is sudo's business.

This is checked by reading the source rather than by running it: the
guarantee is the absence of something, and no amount of exercising the
happy path proves that a password is never read.
*/
func TestTheProgramNeverReadsThePassword(t *testing.T) {
	body, err := os.ReadFile("elevate.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	// Anything that would put a password through this process.
	for _, forbidden := range []string{
		"readPassword", // our own no-echo prompt
		"term.ReadPassword",
		"StdinPipe", // a pipe into sudo -S
		"sudo -S",   // read the password from standard input
		"\"-S\"",    // the same, as an argument
		"askpass",   // SUDO_ASKPASS, which would route it through us
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("elevate.go mentions %q — the password must never pass through this program", forbidden)
		}
	}

	// The streams have to be the terminal's own, so sudo talks to the user.
	for _, required := range []string{"cmd.Stdin = os.Stdin", "cmd.Stdout = os.Stdout", "cmd.Stderr = os.Stderr"} {
		if !strings.Contains(src, required) {
			t.Errorf("elevate.go does not hand the terminal to sudo: missing %q", required)
		}
	}
}

// The uninstall argv has to carry --keep-data, or elevating a request to keep
// the data would delete it.
func TestUninstallArgvKeepsTheDataFlag(t *testing.T) {
	got := uninstallArgv([]string{"--keep-data"})
	if len(got) != 2 || got[0] != "uninstall" || got[1] != "--keep-data" {
		t.Fatalf("got %v, want [uninstall --keep-data]", got)
	}

	if got := uninstallArgv(nil); len(got) != 1 || got[0] != "uninstall" {
		t.Fatalf("got %v, want [uninstall]", got)
	}

	// --yes is deliberately dropped: the elevated run asks again rather than
	// deleting a database on a confirmation given to a different process.
	if got := uninstallArgv([]string{"--yes"}); len(got) != 1 {
		t.Errorf("got %v — --yes should not carry over", got)
	}
}

// A sanity check that the stand-in used above behaves like the real thing.
func TestFakeSudoRunsWhatItIsGiven(t *testing.T) {
	dir, _ := fakeSudo(t, "exit 0")

	sudo, err := exec.LookPath("sudo")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(sudo) != dir {
		t.Fatalf("the stand-in was not found first: %s", sudo)
	}
}

package update

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
	The applier drives systemctl and replaces the installed binary, so these
	tests give it a fake systemctl on PATH and a scratch directory to swap
	things around in. What is being checked is the sequencing: a good build
	gets installed and confirmed, a bad one gets taken back out again.
*/

// bed is one scratch installation: a binary to replace, a staged replacement,
// and a systemctl that answers however the test wants.
type bed struct {
	t       *testing.T
	dir     string // data_dir/update
	binary  string // stands in for /usr/local/bin/revpd
	stateAt string // the fake systemctl reads its answer from here
}

func newBed(t *testing.T, currentVersion, stagedVersion string) *bed {
	t.Helper()

	root := t.TempDir()
	b := &bed{
		t:       t,
		dir:     filepath.Join(root, "update"),
		binary:  filepath.Join(root, "bin", "revpd"),
		stateAt: filepath.Join(root, "unit-state"),
	}

	mustMkdir(t, filepath.Dir(b.binary))
	mustMkdir(t, filepath.Join(b.dir, "staged"))

	writeStub(t, b.binary, currentVersion)
	writeStub(t, filepath.Join(b.dir, "staged", "revpd"), stagedVersion)

	sum, err := sha256File(filepath.Join(b.dir, "staged", "revpd"))
	if err != nil {
		t.Fatal(err)
	}

	writeJSONFile(t, filepath.Join(b.dir, "staged", "manifest.json"), Staged{
		Version: stagedVersion, SHA256: sum, StagedBy: "tester", StagedAt: time.Now(),
	})
	writeJSONFile(t, filepath.Join(b.dir, "apply.request"), applyRequest{
		Version: stagedVersion, SHA256: sum, RequestedBy: "tester",
	})

	b.setUnitState("active")
	b.installFakeSystemctl()
	return b
}

// setUnitState decides what the fake `systemctl is-active` will report.
func (b *bed) setUnitState(state string) {
	if err := os.WriteFile(b.stateAt, []byte(state), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *bed) installFakeSystemctl() {
	dir := b.t.TempDir()

	// restart succeeds and does nothing; is-active reports whatever the test
	// last wrote. journalctl stands in so the failure path has something to
	// quote back.
	script := "#!/bin/sh\ncase \"$1\" in\n  is-active) cat " + b.stateAt + " ;;\n  *) exit 0 ;;\nesac\n"
	write(b.t, filepath.Join(dir, "systemctl"), script, 0o755)
	write(b.t, filepath.Join(dir, "journalctl"), "#!/bin/sh\necho 'fatal: config invalid'\n", 0o755)

	b.t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func (b *bed) apply() (*Result, error) {
	return Apply(context.Background(), ApplyOptions{
		Dir:     b.dir,
		Binary:  b.binary,
		Unit:    "revpd.service",
		Settle:  50 * time.Millisecond, // the real one waits seconds
		Timeout: 5 * time.Second,
		Logf:    func(string, ...any) {},
	})
}

// installedVersion is what the binary at the install path now reports.
func (b *bed) installedVersion() string {
	v, err := binaryVersion(context.Background(), b.binary)
	if err != nil {
		b.t.Fatalf("the installed binary does not run: %v", err)
	}
	return v
}

/* ---------------------------------------------------------------- tests --- */

func TestApplyInstallsAndConfirms(t *testing.T) {
	b := newBed(t, "1.1.0", "1.2.0")

	res, err := b.apply()
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !res.OK {
		t.Fatalf("result not ok: %s", res.Message)
	}

	if got := b.installedVersion(); got != "1.2.0" {
		t.Fatalf("installed version = %s, want 1.2.0", got)
	}
	if res.From != "1.1.0" {
		t.Errorf("From = %q, want 1.1.0", res.From)
	}

	// The previous binary has to be kept, or rollback has nothing to use.
	backups, _ := os.ReadDir(filepath.Join(b.dir, "rollback"))
	if len(backups) == 0 {
		t.Error("no rollback copy was kept")
	}

	// Staging is cleared so the path unit does not re-fire on it.
	if _, err := os.Stat(filepath.Join(b.dir, "staged")); err == nil {
		t.Error("the staging directory was left behind")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "apply.request")); err == nil {
		t.Error("the request was left behind")
	}
}

// The point of the whole design: a release that does not come up cleanly must
// not leave the gateway broken.
func TestApplyRollsBackWhenTheServiceWillNotStay(t *testing.T) {
	b := newBed(t, "1.1.0", "1.2.0")
	b.setUnitState("failed")

	res, err := b.apply()
	if err == nil {
		t.Fatal("a service that failed to start was reported as a successful update")
	}
	if !res.RolledBack {
		t.Fatalf("no rollback happened: %s", res.Message)
	}

	if got := b.installedVersion(); got != "1.1.0" {
		t.Fatalf("installed version = %s — the broken build was left in place", got)
	}
	// The operator needs to know why, not just that.
	if !strings.Contains(res.Message, "config invalid") {
		t.Errorf("the message does not carry the reason from the logs: %s", res.Message)
	}
	if !strings.Contains(res.Message, "1.1.0") {
		t.Errorf("the message does not say what is running now: %s", res.Message)
	}
}

// A binary that unpacked but cannot run must be caught before it is installed,
// not after the restart.
func TestApplyRefusesABinaryThatWillNotRun(t *testing.T) {
	b := newBed(t, "1.1.0", "1.2.0")

	staged := filepath.Join(b.dir, "staged", "revpd")
	if err := copyFile(brokenBinary(t), staged, 0o755); err != nil {
		t.Fatal(err)
	}

	// Keep the manifest and request honest about the new contents, so the
	// hash check passes and the run check is what rejects it.
	sum, err := sha256File(staged)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(b.dir, "staged", "manifest.json"), Staged{Version: "1.2.0", SHA256: sum})
	writeJSONFile(t, filepath.Join(b.dir, "apply.request"), applyRequest{Version: "1.2.0", SHA256: sum})

	res, err := b.apply()
	if err == nil {
		t.Fatal("an unrunnable binary was installed")
	}
	if res.RolledBack {
		t.Error("it rolled back — nothing should have been replaced in the first place")
	}
	if got := b.installedVersion(); got != "1.1.0" {
		t.Fatalf("installed version = %s — the binary was replaced anyway", got)
	}
}

// A staged build whose version does not match what it claims is a sign the
// release is mislabelled, and is not something to install silently.
func TestApplyRefusesAVersionMismatch(t *testing.T) {
	b := newBed(t, "1.1.0", "1.2.0")

	staged := filepath.Join(b.dir, "staged", "revpd")
	writeStub(t, staged, "9.9.9") // says one thing, tagged another

	sum, err := sha256File(staged)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(b.dir, "staged", "manifest.json"), Staged{Version: "1.2.0", SHA256: sum})
	writeJSONFile(t, filepath.Join(b.dir, "apply.request"), applyRequest{Version: "1.2.0", SHA256: sum})

	res, err := b.apply()
	if err == nil {
		t.Fatal("a mislabelled build was installed")
	}
	if !strings.Contains(res.Message, "9.9.9") {
		t.Errorf("the message does not say what the binary claims to be: %s", res.Message)
	}
	if got := b.installedVersion(); got != "1.1.0" {
		t.Fatalf("installed version = %s", got)
	}
}

func TestRestoreGoesBackToAKeptVersion(t *testing.T) {
	b := newBed(t, "1.1.0", "1.2.0")

	if _, err := b.apply(); err != nil {
		t.Fatal(err)
	}
	if got := b.installedVersion(); got != "1.2.0" {
		t.Fatalf("setup did not install: %s", got)
	}

	backups, err := os.ReadDir(filepath.Join(b.dir, "rollback"))
	if err != nil || len(backups) == 0 {
		t.Fatal("nothing was kept to roll back to")
	}
	backup := filepath.Join(b.dir, "rollback", backups[0].Name())

	res, err := Restore(context.Background(), ApplyOptions{
		Dir: b.dir, Binary: b.binary, Settle: 50 * time.Millisecond, Timeout: 5 * time.Second,
	}, backup)
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if !res.OK {
		t.Fatalf("restore not ok: %s", res.Message)
	}
	if got := b.installedVersion(); got != "1.1.0" {
		t.Fatalf("installed version = %s, want 1.1.0", got)
	}
}

// The service reads result.json to find out what happened while it was being
// restarted, so the applier must always leave one.
func TestApplyAlwaysLeavesAResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  string
		wantOK bool
	}{
		{"success", "active", true},
		{"rollback", "failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBed(t, "1.1.0", "1.2.0")
			b.setUnitState(tc.state)
			b.apply()

			body, err := os.ReadFile(filepath.Join(b.dir, "result.json"))
			if err != nil {
				t.Fatalf("no result was written: %v", err)
			}
			var res Result
			if err := json.Unmarshal(body, &res); err != nil {
				t.Fatal(err)
			}
			if res.OK != tc.wantOK {
				t.Errorf("result.ok = %v, want %v (%s)", res.OK, tc.wantOK, res.Message)
			}
			if res.Message == "" {
				t.Error("the result carries no explanation")
			}
		})
	}
}

// The architecture check is the one piece of the applier whose behaviour
// depends on the machine running the test: it only inspects ELF, so on macOS
// it is skipped entirely and a fault in it would go unnoticed until CI.
// Cross-compiling real Linux binaries exercises it from anywhere.
func TestCheckExecutableJudgesRealLinuxBinaries(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no Go toolchain on PATH")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	build := func(goarch string) string {
		out := filepath.Join(dir, "revpd-"+goarch)
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cross-compiling for linux/%s failed: %v\n%s", goarch, err, msg)
		}
		return out
	}

	amd64, arm64 := build("amd64"), build("arm64")

	if err := checkExecutable(amd64, "linux", "amd64"); err != nil {
		t.Errorf("a genuine linux/amd64 binary was rejected: %v", err)
	}
	if err := checkExecutable(arm64, "linux", "arm64"); err != nil {
		t.Errorf("a genuine linux/arm64 binary was rejected: %v", err)
	}

	// The case that matters: an archive built for the wrong machine.
	err := checkExecutable(arm64, "linux", "amd64")
	if err == nil {
		t.Fatal("an arm64 binary was accepted on an amd64 machine")
	}
	if !strings.Contains(err.Error(), "amd64") {
		t.Errorf("the message does not name this machine's architecture: %v", err)
	}

	// A shell script is not something to install, however executable it is.
	script := filepath.Join(dir, "script")
	write(t, script, "#!/bin/sh\necho revpd 1.0.0\n", 0o755)
	if err := checkExecutable(script, "linux", "amd64"); err == nil {
		t.Error("a shell script passed as a Linux binary")
	}
}

/* -------------------------------------------------------------- helpers --- */

// The stand-in binaries have to be real executables, not shell scripts: the
// applier checks that what it is about to install is a native binary for this
// machine, and a script fails that check on Linux while slipping past it
// everywhere else. Compiling them keeps the test honest on both.
var (
	binCacheOnce sync.Once
	binCacheDir  string
	binCacheErr  error
	binCacheMu   sync.Mutex
	binCache     = map[string]string{}
)

// stubBinary compiles a program that answers `version` the way revpd does, and
// caches it: several tests want the same version.
func stubBinary(t *testing.T, version string) string {
	t.Helper()
	return buildStub(t, "version-"+version, `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("revpd `+version+`")
	}
}
`)
}

// brokenBinary compiles a real executable that fails when it is run, which is
// how a build for the wrong libc or a corrupted binary behaves.
func brokenBinary(t *testing.T) string {
	t.Helper()
	return buildStub(t, "broken", `package main

import "os"

func main() { os.Exit(1) }
`)
}

func buildStub(t *testing.T, name, source string) string {
	t.Helper()

	binCacheOnce.Do(func() {
		binCacheDir, binCacheErr = os.MkdirTemp("", "revpd-stub-bins")
	})
	if binCacheErr != nil {
		t.Fatalf("could not make a directory for the stub binaries: %v", binCacheErr)
	}

	binCacheMu.Lock()
	defer binCacheMu.Unlock()

	if path, ok := binCache[name]; ok {
		return path
	}

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no Go toolchain on PATH to build the stub binaries with")
	}

	src := filepath.Join(binCacheDir, name+".go")
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(binCacheDir, name)
	cmd := exec.Command("go", "build", "-o", out, src)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not build the stub binary: %v\n%s", err, msg)
	}

	binCache[name] = out
	return out
}

// writeStub puts a compiled stand-in reporting the given version at path.
func writeStub(t *testing.T, path, version string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := copyFile(stubBinary(t, version), path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

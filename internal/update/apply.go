package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ApplyOptions configure the privileged half of an update.
type ApplyOptions struct {
	// Dir is data_dir/update, where the unprivileged half left the request.
	Dir string

	// Binary is the file to replace. Empty means this process's own path,
	// which is what systemd started and therefore what must be swapped.
	Binary string

	// Unit is the systemd service to restart. Empty means revpd.service.
	Unit string

	// Settle is how long the restarted service has to stay up before the
	// update counts as good. A crash loop takes a few seconds to show itself,
	// so returning the moment systemd says "active" would call a broken build
	// a success.
	Settle time.Duration

	// Timeout caps the wait for the service to come back at all.
	Timeout time.Duration

	Logf func(format string, args ...any)
}

// ErrNoRequest means there is nothing waiting to be installed. The applier is
// started by a path unit, which can fire on a stale marker, so this is a
// normal outcome rather than a fault.
var ErrNoRequest = errors.New("no update has been requested")

// Apply installs the staged binary, restarts the service and verifies that it
// came back. If anything fails at any point the previous binary is put back
// and the service restarted with it, so a bad release costs a restart rather
// than the gateway.
//
// It must run as root: the service itself is sandboxed away from /usr.
func Apply(ctx context.Context, o ApplyOptions) (*Result, error) {
	o = o.withDefaults()
	log := o.Logf

	req, err := readRequest(filepath.Join(o.Dir, "apply.request"))
	if err != nil {
		return nil, err
	}

	staged := filepath.Join(o.Dir, "staged", "revpd")
	manifest, err := readManifest(filepath.Join(o.Dir, "staged", "manifest.json"))
	if err != nil {
		return o.fail(req.Version, "", "the staged update is incomplete: %v", err)
	}

	if manifest.Version != req.Version {
		return o.fail(req.Version, "",
			"the request asks for %s but the staged binary is %s — the staging directory was changed underneath the request",
			req.Version, manifest.Version)
	}

	// Re-verify rather than trust the request. The unprivileged half wrote
	// both files, so this is what keeps a compromised service account from
	// talking root into installing something it did not download.
	sum, err := sha256File(staged)
	if err != nil {
		return o.fail(req.Version, "", "the staged binary could not be read: %v", err)
	}
	if sum != manifest.SHA256 || sum != req.SHA256 {
		return o.fail(req.Version, "",
			"the staged binary does not match the hash it was verified with — refusing to install it")
	}
	log("verified %s (sha256 %s…)", req.Version, sum[:12])

	if err := checkExecutable(staged, runtimeOS(), runtimeArch()); err != nil {
		return o.fail(req.Version, "", "%v", err)
	}

	// Run it once before trusting it with the service. A binary that cannot
	// even print its version is not going anywhere near /usr/local/bin.
	reported, err := binaryVersion(ctx, staged)
	if err != nil {
		return o.fail(req.Version, "", "the staged binary does not run on this machine: %v", err)
	}
	if got, want := reported, strings.TrimPrefix(req.Version, "v"); got != want && got != req.Version {
		return o.fail(req.Version, "",
			"the staged binary reports version %q but the release is %s — refusing to install a mismatched build",
			got, req.Version)
	}

	previous, _ := binaryVersion(ctx, o.Binary)
	log("installing %s over %s at %s", req.Version, orUnknown(previous), o.Binary)

	backup := filepath.Join(o.Dir, "rollback", "revpd-"+orUnknown(previous))
	if err := os.MkdirAll(filepath.Dir(backup), 0o750); err != nil {
		return o.fail(req.Version, previous, "could not create the rollback directory: %v", err)
	}
	if err := copyFile(o.Binary, backup, 0o755); err != nil {
		return o.fail(req.Version, previous, "could not back up the current binary: %v", err)
	}

	if err := installBinary(staged, o.Binary); err != nil {
		return o.fail(req.Version, previous, "could not replace %s: %v", o.Binary, err)
	}

	if err := o.restart(ctx); err != nil {
		log("restart failed, rolling back: %v", err)
		return o.rollback(ctx, backup, req.Version, previous, "the service would not restart with %s: %v", req.Version, err)
	}

	if err := o.waitHealthy(ctx); err != nil {
		log("new version did not stay up, rolling back: %v", err)
		return o.rollback(ctx, backup, req.Version, previous, "%v", err)
	}

	os.RemoveAll(filepath.Join(o.Dir, "staged"))
	o.pruneRollbacks()

	return o.finish(&Result{
		Version: req.Version,
		From:    previous,
		OK:      true,
		Message: fmt.Sprintf("Updated to %s and the service came back healthy.", req.Version),
		At:      time.Now(),
	})
}

func (o ApplyOptions) withDefaults() ApplyOptions {
	if o.Binary == "" {
		if self, err := os.Executable(); err == nil {
			// Resolve symlinks so the real file is replaced, not the link.
			if real, err := filepath.EvalSymlinks(self); err == nil {
				o.Binary = real
			} else {
				o.Binary = self
			}
		}
	}
	if o.Unit == "" {
		o.Unit = "revpd.service"
	}
	if o.Settle <= 0 {
		o.Settle = 8 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 90 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// Restore puts a specific kept binary back and restarts the service. It is the
// manual escape hatch for an update that installed cleanly but turned out to
// misbehave later, which no automatic health check can catch.
func Restore(ctx context.Context, o ApplyOptions, backup string) (*Result, error) {
	o = o.withDefaults()

	if _, err := binaryVersion(ctx, backup); err != nil {
		return o.fail("", "", "%s does not run on this machine, so it is not safe to go back to: %v", backup, err)
	}

	current, _ := binaryVersion(ctx, o.Binary)
	target, _ := binaryVersion(ctx, backup)

	if err := installBinary(backup, o.Binary); err != nil {
		return o.fail(target, current, "could not put %s back: %v", backup, err)
	}
	if err := o.restart(ctx); err != nil {
		return o.fail(target, current, "%s was put back but the service would not restart: %v", orUnknown(target), err)
	}
	if err := o.waitHealthy(ctx); err != nil {
		return o.fail(target, current, "%s was put back but did not stay up: %v", orUnknown(target), err)
	}

	return o.finish(&Result{
		Version: target,
		From:    current,
		OK:      true,
		Message: fmt.Sprintf("Rolled back to %s and the service came back healthy.", orUnknown(target)),
		At:      time.Now(),
	})
}

/* -------------------------------------------------------------- restart --- */

func (o ApplyOptions) restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "systemctl", "restart", o.Unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v%s", o.Unit, err, indented(out))
	}
	return nil
}

// waitHealthy holds the update open until the service has been up long enough
// to prove it is not crash-looping. Restart=on-failure means a broken build
// alternates between activating and failed, which only shows over a few
// seconds — so "active" once is not enough to go on.
func (o ApplyOptions) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(o.Timeout)
	var stableSince time.Time

	for time.Now().Before(deadline) {
		state := unitState(ctx, o.Unit)

		switch state {
		case "active":
			if stableSince.IsZero() {
				stableSince = time.Now()
			}
			if time.Since(stableSince) >= o.Settle {
				return nil
			}
		case "failed":
			return fmt.Errorf("the service failed to start after the update: %s", lastLogLines(ctx, o.Unit))
		default:
			// activating, deactivating, inactive: not settled yet.
			stableSince = time.Time{}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}

	return fmt.Errorf("the service did not stay up for %s after the update (it is %q): %s",
		o.Settle, unitState(ctx, o.Unit), lastLogLines(ctx, o.Unit))
}

func unitState(ctx context.Context, unit string) string {
	// is-active exits non-zero for every state except active, so the output is
	// what matters, not the exit code.
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out))
}

// lastLogLines gives the operator the reason rather than just the verdict.
func lastLogLines(ctx context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", "5", "--no-pager", "-o", "cat").Output()
	if err != nil || len(out) == 0 {
		return "check journalctl -u " + unit
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.Join(lines, " / ")
}

/* ------------------------------------------------------------- rollback --- */

func (o ApplyOptions) rollback(ctx context.Context, backup, version, previous, format string, args ...any) (*Result, error) {
	reason := fmt.Sprintf(format, args...)

	res := &Result{
		Version:    version,
		From:       previous,
		OK:         false,
		RolledBack: true,
		At:         time.Now(),
	}

	if err := installBinary(backup, o.Binary); err != nil {
		res.RolledBack = false
		res.Message = fmt.Sprintf(
			"%s — and putting %s back failed too (%v). The previous binary is at %s; restore it by hand and run: systemctl restart %s",
			reason, orUnknown(previous), err, backup, o.Unit)
		return o.finish(res)
	}

	if err := o.restart(ctx); err != nil {
		res.Message = fmt.Sprintf(
			"%s — %s was put back but the service would not restart with it either (%v). Check: journalctl -u %s",
			reason, orUnknown(previous), err, o.Unit)
		return o.finish(res)
	}

	res.Message = fmt.Sprintf("%s — rolled back to %s, which is running again.", reason, orUnknown(previous))
	return o.finish(res)
}

// pruneRollbacks keeps the two most recent backups. One is enough to undo the
// last update; the second covers an update applied on top of a bad one.
func (o ApplyOptions) pruneRollbacks() {
	dir := filepath.Join(o.Dir, "rollback")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= 2 {
		return
	}

	type aged struct {
		path string
		mod  time.Time
	}
	var files []aged
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, aged{filepath.Join(dir, e.Name()), info.ModTime()})
	}
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].mod.After(files[i].mod) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	for _, f := range files[min(2, len(files)):] {
		os.Remove(f.path)
	}
}

/* ---------------------------------------------------------------- files --- */

// installBinary replaces dest atomically. The new file is written alongside
// the target so the rename cannot cross a filesystem boundary, and a reader
// mid-exec keeps the old inode rather than seeing a half-written file.
func installBinary(src, dest string) error {
	tmp := filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".new")
	if err := copyFile(src, tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// OpenFile honours the umask, which would leave the binary unreadable to
	// the service account on a tight one.
	return os.Chmod(dest, mode)
}

func binaryVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", err
	}
	// `revpd version` prints "revpd <version>".
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", fmt.Errorf("it printed %q instead of a version", strings.TrimSpace(string(out)))
	}
	return fields[1], nil
}

/* --------------------------------------------------------------- request -- */

type applyRequest struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	RequestedBy string `json:"requested_by"`
}

func readRequest(path string) (*applyRequest, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoRequest
	}
	if err != nil {
		return nil, fmt.Errorf("read the update request: %w", err)
	}

	var req applyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("the update request is not readable and has been discarded: %w", err)
	}
	if req.Version == "" || req.SHA256 == "" {
		os.Remove(path)
		return nil, errors.New("the update request names no version and has been discarded")
	}
	return &req, nil
}

func readManifest(path string) (*Staged, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Staged
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

/* ---------------------------------------------------------------- result -- */

func (o ApplyOptions) fail(version, from, format string, args ...any) (*Result, error) {
	return o.finish(&Result{
		Version: version,
		From:    from,
		OK:      false,
		Message: fmt.Sprintf(format, args...),
		At:      time.Now(),
	})
}

// finish records the outcome where the service will find it after the restart,
// and clears the request so the path unit does not fire on it again.
func (o ApplyOptions) finish(res *Result) (*Result, error) {
	body, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		path := filepath.Join(o.Dir, "result.json")
		if err := writeFileAtomic(path, body, 0o640); err == nil {
			// Written by root into a directory the service owns, so hand it
			// over or the service cannot read its own outcome.
			if uid, gid, ok := ownerOf(o.Dir); ok {
				os.Chown(path, uid, gid)
			}
		}
	}

	os.Remove(filepath.Join(o.Dir, "apply.request"))

	if !res.OK {
		return res, errors.New(res.Message)
	}
	return res, nil
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func indented(out []byte) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return ""
	}
	return ": " + strings.ReplaceAll(s, "\n", " / ")
}

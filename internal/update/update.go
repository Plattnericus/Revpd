// Package update keeps the running gateway on the latest published release.
//
// The work is split in two on purpose. This half runs inside the service,
// which is unprivileged and sandboxed by the unit file: it may talk to GitHub
// and write inside data_dir, and that is all it needs to download a release,
// verify it and park it. Replacing /usr/local/bin/revpd and restarting the
// unit needs root, so it happens in the applier (see apply.go), which systemd
// starts when this half asks for it.
//
// Nothing is ever installed on the strength of the download alone: the archive
// is checked against the checksums file published with the release, the binary
// inside it is checked for the right architecture, and the applier re-verifies
// the hash before it swaps anything and rolls back if the new build does not
// come up.
package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Manager owns the updater state for one installation.
type Manager struct {
	dir     string // data_dir/update
	current string // version this process was built as
	client  *Client

	goos, goarch string

	mu sync.Mutex
	st State

	// busy serialises check/stage so two dashboard clicks cannot download the
	// same release twice into the same directory.
	busy sync.Mutex
}

// Options configure a Manager.
type Options struct {
	DataDir string
	Version string
	Repo    string
	Token   string
	HTTP    *http.Client
}

func NewManager(o Options) (*Manager, error) {
	dir := filepath.Join(o.DataDir, "update")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create update directory: %w", err)
	}

	m := &Manager{
		dir:     dir,
		current: o.Version,
		client:  &Client{Repo: o.Repo, Token: o.Token, HTTP: o.HTTP},
		goos:    runtime.GOOS,
		goarch:  runtime.GOARCH,
	}
	m.st = loadState(dir)
	m.absorbResult()
	return m, nil
}

// Current is the version this process is running.
func (m *Manager) Current() string { return m.current }

// Repo is where updates come from.
func (m *Manager) Repo() string { return m.client.repo() }

// Dir is the updater's working directory.
func (m *Manager) Dir() string { return m.dir }

// State returns a copy of the current picture.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.absorbResultLocked()
	return m.st
}

func (m *Manager) update(f func(*State)) {
	m.mu.Lock()
	f(&m.st)
	st := m.st
	m.mu.Unlock()

	if err := saveState(m.dir, st); err != nil {
		// Losing the state file costs a re-check, nothing more.
		_ = err
	}
}

// absorbResult picks up what the privileged applier left behind, which is the
// only way this process learns whether the last install worked — by then it
// was a different process entirely.
func (m *Manager) absorbResult() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.absorbResultLocked()
}

func (m *Manager) absorbResultLocked() {
	body, err := os.ReadFile(m.resultPath())
	if err != nil {
		return
	}
	var res Result
	if err := json.Unmarshal(body, &res); err != nil {
		os.Remove(m.resultPath())
		return
	}

	m.st.Last = &res
	m.st.Staged = nil
	m.st.Downloaded, m.st.Total = 0, 0
	if res.OK {
		m.st.Phase = PhaseIdle
		m.st.Available = nil
	} else {
		m.st.Phase = PhaseFailed
	}
	os.Remove(m.resultPath())
	_ = saveState(m.dir, m.st)
}

func (m *Manager) resultPath() string  { return filepath.Join(m.dir, "result.json") }
func (m *Manager) requestPath() string { return filepath.Join(m.dir, "apply.request") }
func (m *Manager) stagedDir() string   { return filepath.Join(m.dir, "staged") }
func (m *Manager) stagedBin() string   { return filepath.Join(m.stagedDir(), "revpd") }

/* ---------------------------------------------------------------- check --- */

// Check asks GitHub what the newest release is and records whether it is newer
// than what is running. It never downloads anything.
func (m *Manager) Check(ctx context.Context, prerelease bool) (*Available, error) {
	m.busy.Lock()
	defer m.busy.Unlock()

	m.update(func(s *State) {
		if s.Phase == PhaseIdle || s.Phase == PhaseFailed {
			s.Phase = PhaseChecking
		}
	})

	rel, err := m.client.Latest(ctx, prerelease)
	if err != nil {
		m.recordCheckError(err)
		return nil, err
	}

	newer, ok := Newer(m.current, rel.Tag)
	if !ok {
		// An untagged build has no place in the ordering, so there is nothing
		// truthful to say about whether the release is newer than it.
		err := failf(ReasonUnorderable, nil,
			"this gateway is running %q, which is not a released version, so it cannot be compared with %s. Updating would replace a build somebody installed deliberately; install a release first if that is what you want.",
			m.current, rel.Tag)
		m.recordCheckError(err)
		return nil, err
	}

	var avail *Available
	if newer {
		avail = &Available{
			Version:     rel.Tag,
			Notes:       rel.Notes,
			URL:         rel.HTMLURL,
			PublishedAt: rel.PublishedAt,
			Prerelease:  rel.Prerelease,
		}
		if a := rel.Asset(m.assetName(rel.Tag)); a != nil {
			avail.Size = a.Size
			avail.AssetReady = true
		}
	}

	m.update(func(s *State) {
		s.LastCheck = time.Now()
		s.LastCheckErr, s.LastCheckKind = "", ""
		s.Available = avail
		if s.Phase == PhaseChecking {
			s.Phase = PhaseIdle
		}
		if s.Staged != nil {
			s.Phase = PhaseStaged
		}
	})
	return avail, nil
}

func (m *Manager) recordCheckError(err error) {
	reason := ReasonNetwork
	var f *Failure
	if errors.As(err, &f) {
		reason = f.Reason
	}
	m.update(func(s *State) {
		s.LastCheck = time.Now()
		s.LastCheckErr = err.Error()
		s.LastCheckKind = reason
		if s.Phase == PhaseChecking {
			s.Phase = PhaseIdle
		}
	})
}

// assetName is the archive this build needs. Both halves of the release
// pipeline derive it the same way, so the name cannot drift.
func (m *Manager) assetName(tag string) string {
	return fmt.Sprintf("revpd_%s_%s_%s.tar.gz", strings.TrimPrefix(tag, "v"), m.goos, m.goarch)
}

/* ---------------------------------------------------------------- stage --- */

// Stage downloads the release, verifies it against the published checksums and
// parks the binary next to a manifest. Nothing outside data_dir is touched, so
// this is safe to do while the gateway is serving traffic.
func (m *Manager) Stage(ctx context.Context, tag, by string, automatic bool) (*Staged, error) {
	m.busy.Lock()
	defer m.busy.Unlock()

	rel, err := m.client.ByTag(ctx, tag)
	if err != nil {
		m.setFailed(err)
		return nil, err
	}

	name := m.assetName(rel.Tag)
	asset := rel.Asset(name)
	if asset == nil {
		var err error
		if len(rel.Assets) == 0 {
			err = failf(ReasonNoAssets, nil,
				"release %s has no files attached to it yet. If it was published in the last few minutes its build is probably still running — try again shortly.",
				rel.Tag)
		} else {
			err = failf(ReasonNoBuild, nil,
				"release %s has no build for %s/%s. It needs %s; it contains: %s.",
				rel.Tag, m.goos, m.goarch, name, strings.Join(rel.AssetNames(), ", "))
		}
		m.setFailed(err)
		return nil, err
	}

	m.update(func(s *State) {
		s.Phase = PhaseDownloading
		s.Downloaded, s.Total = 0, asset.Size
	})

	if err := os.RemoveAll(m.stagedDir()); err != nil {
		return nil, m.setFailed(failf(ReasonCorrupt, err, "could not clear the staging directory: %v", err))
	}
	if err := os.MkdirAll(m.stagedDir(), 0o750); err != nil {
		return nil, m.setFailed(failf(ReasonCorrupt, err, "could not create the staging directory: %v", err))
	}

	archive := filepath.Join(m.stagedDir(), name)
	sum, err := m.download(ctx, asset.URL, archive)
	if err != nil {
		return nil, m.setFailed(err)
	}

	m.update(func(s *State) { s.Phase = PhaseVerifying })

	// The checksums file is published with the release and fetched separately,
	// so a corrupted or swapped archive fails here rather than on restart.
	if err := m.verifyChecksum(ctx, rel, name, sum); err != nil {
		return nil, m.setFailed(err)
	}

	if err := extractBinary(archive, m.stagedBin()); err != nil {
		return nil, m.setFailed(err)
	}
	os.Remove(archive)

	if err := checkExecutable(m.stagedBin(), m.goos, m.goarch); err != nil {
		return nil, m.setFailed(err)
	}

	binSum, err := sha256File(m.stagedBin())
	if err != nil {
		return nil, m.setFailed(failf(ReasonCorrupt, err, "could not hash the unpacked binary: %v", err))
	}

	staged := &Staged{
		Version:   rel.Tag,
		SHA256:    binSum,
		Path:      m.stagedBin(),
		StagedAt:  time.Now(),
		StagedBy:  by,
		Automatic: automatic,
	}

	body, err := json.MarshalIndent(staged, "", "  ")
	if err != nil {
		return nil, m.setFailed(failf(ReasonCorrupt, err, "could not write the staging manifest: %v", err))
	}
	if err := writeFileAtomic(filepath.Join(m.stagedDir(), "manifest.json"), body, 0o640); err != nil {
		return nil, m.setFailed(failf(ReasonCorrupt, err, "could not write the staging manifest: %v", err))
	}

	m.update(func(s *State) {
		s.Phase = PhaseStaged
		s.Staged = staged
		s.Downloaded, s.Total = 0, 0
	})
	return staged, nil
}

func (m *Manager) setFailed(err error) error {
	reason := ReasonNetwork
	var f *Failure
	if errors.As(err, &f) {
		reason = f.Reason
	}
	m.update(func(s *State) {
		s.Phase = PhaseFailed
		s.LastCheckErr = err.Error()
		s.LastCheckKind = reason
		s.Downloaded, s.Total = 0, 0
	})
	return err
}

// download streams the asset to disk, hashing as it goes so the file is never
// read twice, and reporting progress for the dashboard.
func (m *Manager) download(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", failf(ReasonNetwork, err, "could not build the download request")
	}
	req.Header.Set("User-Agent", "revpd")
	if tok := m.client.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := m.client.httpClient()
	// Downloads are much larger than API calls and deserve their own budget.
	dl := *client
	dl.Timeout = 15 * time.Minute

	resp, err := dl.Do(req)
	if err != nil {
		return "", networkFailure(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", failf(ReasonServer, nil,
			"downloading %s failed with HTTP %d. The release lists the file, so a proxy that rewrites downloads is the likeliest cause.",
			filepath.Base(dest), resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", failf(ReasonCorrupt, err, "could not write into the staging directory: %v", err)
	}
	defer f.Close()

	h := sha256.New()
	counter := &progressWriter{m: m}
	if _, err := io.Copy(io.MultiWriter(f, h, counter), resp.Body); err != nil {
		return "", failf(ReasonNetwork, err, "the download stopped part-way through: %v", err)
	}
	if err := f.Sync(); err != nil {
		return "", failf(ReasonCorrupt, err, "the download could not be flushed to disk: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type progressWriter struct {
	m    *Manager
	n    int64
	last time.Time
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	// Persisting on every chunk would write the state file thousands of times.
	if time.Since(w.last) > 400*time.Millisecond {
		w.last = time.Now()
		n := w.n
		w.m.update(func(s *State) { s.Downloaded = n })
	}
	return len(p), nil
}

// verifyChecksum holds the archive against the checksums file published with
// the release. A release without one is not installed: an unverified binary is
// exactly the thing this gateway exists to keep off the network.
func (m *Manager) verifyChecksum(ctx context.Context, rel *Release, name, sum string) error {
	asset := rel.Asset("checksums.txt")
	if asset == nil {
		return failf(ReasonCorrupt, nil,
			"release %s publishes no checksums.txt, so the download cannot be verified. Refusing to install it.",
			rel.Tag)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return failf(ReasonNetwork, err, "could not build the checksums request")
	}
	req.Header.Set("User-Agent", "revpd")
	if tok := m.client.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := m.client.httpClient().Do(req)
	if err != nil {
		return networkFailure(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return failf(ReasonServer, nil,
			"release %s lists checksums.txt but it could not be downloaded (HTTP %d). Refusing to install an unverified binary.",
			rel.Tag, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return failf(ReasonNetwork, err, "reading checksums.txt failed: %v", err)
	}

	want := ""
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return failf(ReasonCorrupt, nil,
			"checksums.txt in release %s has no entry for %s, so the archive is not vouched for by the release. Refusing to install it.",
			rel.Tag, name)
	}
	if !strings.EqualFold(want, sum) {
		return failf(ReasonCorrupt, nil,
			"checksum mismatch on %s — the download was corrupted or tampered with, and has been discarded. Expected %s, got %s.",
			name, want, sum)
	}
	return nil
}

/* -------------------------------------------------------------- request --- */

// ErrNoApplier means the privileged half is not installed, so a staged update
// has nothing to pick it up.
var ErrNoApplier = errors.New("the privileged updater is not installed")

// RequestApply asks the privileged applier to install what is staged.
//
// It writes a marker rather than doing the work: this process runs as an
// unprivileged user under a unit that mounts /usr read-only, so it could not
// replace the binary even if it tried. A systemd path unit watches the marker
// and starts the applier as root.
func (m *Manager) RequestApply(by string) error {
	st := m.State()
	if st.Staged == nil {
		return errors.New("nothing is staged to install")
	}

	body, err := json.MarshalIndent(map[string]any{
		"version":      st.Staged.Version,
		"sha256":       st.Staged.SHA256,
		"requested_by": by,
		"requested_at": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}

	// The marker is written last and atomically: the applier must never see a
	// half-written request and act on it.
	if err := writeFileAtomic(m.requestPath(), body, 0o640); err != nil {
		return fmt.Errorf("could not ask the updater to install %s: %w", st.Staged.Version, err)
	}

	m.update(func(s *State) { s.Phase = PhaseApplying })
	return nil
}

// RequestRestart asks the privileged helper to restart the service.
//
// Nothing about this is an update, but it needs exactly the same thing an
// update does — root, and a way to reach systemd — so it travels through the
// same request directory rather than growing a second mechanism beside it.
func (m *Manager) RequestRestart(by string) error {
	body, err := json.MarshalIndent(map[string]any{
		"requested_by": by,
		"requested_at": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(m.dir, "restart.request"), body, 0o640); err != nil {
		return fmt.Errorf("could not ask for a restart: %w", err)
	}
	return nil
}

// ApplierInstalled reports whether the privileged half is present. Without it
// an update can be downloaded and verified but never installed, and the
// dashboard should say so before someone waits for a restart that never comes.
func ApplierInstalled() bool {
	for _, p := range []string{
		"/etc/systemd/system/revpd-update.path",
		"/run/systemd/system/revpd-update.path",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

/* ------------------------------------------------------------- archives --- */

// extractBinary pulls exactly the revpd entry out of the archive.
func extractBinary(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return failf(ReasonCorrupt, err, "could not open the downloaded archive: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return failf(ReasonCorrupt, err,
			"the download is not a gzip archive. A captive portal or proxy returning a web page instead of the file looks exactly like this.")
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return failf(ReasonCorrupt, err, "the archive is damaged: %v", err)
		}

		// Only the binary at the root of the archive, by exact name. Anything
		// else — paths, links, directories — is ignored rather than written.
		if hdr.Typeflag != tar.TypeReg || filepath.Clean(hdr.Name) != "revpd" {
			continue
		}

		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o750)
		if err != nil {
			return failf(ReasonCorrupt, err, "could not write the new binary: %v", err)
		}
		// Cap the copy: a decompression bomb should not fill the data volume.
		if _, err := io.Copy(out, io.LimitReader(tr, 512<<20)); err != nil {
			out.Close()
			return failf(ReasonCorrupt, err, "unpacking the new binary failed: %v", err)
		}
		if err := out.Close(); err != nil {
			return failf(ReasonCorrupt, err, "unpacking the new binary failed: %v", err)
		}
		return nil
	}

	return failf(ReasonCorrupt, nil,
		"the archive does not contain a revpd binary at its root. This release is built wrongly.")
}

// checkExecutable confirms the unpacked file is a binary this machine can
// actually run, without executing it. Catching a wrong-architecture build here
// beats finding out when the service fails to restart.
func checkExecutable(path, goos, goarch string) error {
	if goos != "linux" {
		// Only ELF can be inspected this way; elsewhere the applier's
		// run-it-once check is what stands in.
		return nil
	}

	f, err := elf.Open(path)
	if err != nil {
		return failf(ReasonCorrupt, err,
			"the unpacked file is not a Linux executable — the release archive holds the wrong thing")
	}
	defer f.Close()

	want, ok := elfMachines[goarch]
	if !ok {
		return nil
	}
	if f.Machine != want {
		return failf(ReasonNoBuild, nil,
			"the downloaded binary is built for %s, but this machine is %s. Refusing to install it.",
			f.Machine, goarch)
	}
	return nil
}

var elfMachines = map[string]elf.Machine{
	"amd64":   elf.EM_X86_64,
	"arm64":   elf.EM_AARCH64,
	"arm":     elf.EM_ARM,
	"386":     elf.EM_386,
	"riscv64": elf.EM_RISCV,
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

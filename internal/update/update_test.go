package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"v1.0.0", "1.0.0", 0},
		{"1.2", "1.2.0", 0},
		{"1.9.0", "1.10.0", -1},

		// The tag style this repository actually uses. A string compare would
		// call 1.0.001 and 1.0.1 different; they are the same release.
		{"1.0.001", "1.0.1", 0},
		{"v1.0.001", "v1.0.2", -1},
		{"1.0.010", "1.0.9", 1},

		// Pre-releases sort below the final release of the same version.
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0-rc2", "1.0.0-rc10", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0+build9", "1.0.0", 0},
	}

	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q, %q) could not order them", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// An untagged build must never be ordered against a release: reporting it as
// older would let an update silently replace a hand-built binary.
func TestCompareRefusesUnversioned(t *testing.T) {
	for _, v := range []string{"dev", "docker", "", "main", "1.0.0.0.0", "v1.x"} {
		if _, ok := Compare(v, "1.0.0"); ok {
			t.Errorf("Compare(%q, …) claimed to order an unversioned build", v)
		}
		if IsRelease(v) {
			t.Errorf("IsRelease(%q) = true", v)
		}
	}
	if !IsRelease("v1.2.3") {
		t.Error("IsRelease(v1.2.3) = false")
	}
}

/* ------------------------------------------------------------- fake hub --- */

// hub is a stand-in for the GitHub releases API serving one repository.
type hub struct {
	t        *testing.T
	releases []Release
	assets   map[string][]byte // asset name -> body
	server   *httptest.Server
}

func newHub(t *testing.T) *hub {
	h := &hub{t: t, assets: map[string][]byte{}}
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		for _, rel := range h.releases {
			if !rel.Draft && !rel.Prerelease {
				json.NewEncoder(w).Encode(rel)
				return
			}
		}
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})

	mux.HandleFunc("/repos/o/r/releases", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(h.releases)
	})

	mux.HandleFunc("/repos/o/r/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		tag := strings.TrimPrefix(r.URL.Path, "/repos/o/r/releases/tags/")
		for _, rel := range h.releases {
			if rel.Tag == tag {
				json.NewEncoder(w).Encode(rel)
				return
			}
		}
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})

	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := h.assets[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})

	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

// publish attaches an archive and matching checksums.txt to a release.
func (h *hub) publish(tag string, binary []byte, opts ...func(*Release)) {
	name := fmt.Sprintf("revpd_%s_linux_amd64.tar.gz", strings.TrimPrefix(tag, "v"))
	archive := tarGz(h.t, "revpd", binary)

	sum := sha256.Sum256(archive)
	checksums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), name)

	h.assets[name] = archive
	h.assets["checksums.txt"] = []byte(checksums)

	rel := Release{
		Tag:         tag,
		PublishedAt: time.Now(),
		Assets: []Asset{
			{Name: name, URL: h.server.URL + "/dl/" + name, Size: int64(len(archive))},
			{Name: "checksums.txt", URL: h.server.URL + "/dl/checksums.txt"},
		},
	}
	for _, o := range opts {
		o(&rel)
	}
	h.releases = append([]Release{rel}, h.releases...)
}

func (h *hub) manager(t *testing.T, current string) *Manager {
	t.Helper()
	m, err := NewManager(Options{DataDir: t.TempDir(), Version: current, Repo: "o/r"})
	if err != nil {
		t.Fatal(err)
	}
	// Point the client at the fake hub and pin the platform so the test is the
	// same on every machine it runs on.
	m.client.HTTP = h.server.Client()
	m.client.base = h.server.URL + "/repos/"
	m.goos, m.goarch = "linux", "amd64"
	return m
}

func tarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A minimal ELF header for linux/amd64, so checkExecutable has something real
// to inspect without needing a cross-compiler in the test.
func fakeELF() []byte {
	b := make([]byte, 128)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2     // 64-bit
	b[5] = 1     // little endian
	b[6] = 1     // version
	b[16] = 2    // ET_EXEC
	b[18] = 0x3e // EM_X86_64
	b[20] = 1
	return b
}

/* ---------------------------------------------------------------- tests --- */

func TestCheckFindsNewerRelease(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "1.1.0")

	avail, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if avail == nil || avail.Version != "v1.2.0" {
		t.Fatalf("got %+v, want v1.2.0", avail)
	}
	if st := m.State(); st.Available == nil || st.Phase != PhaseIdle {
		t.Fatalf("state not recorded: %+v", st)
	}
}

func TestCheckReportsUpToDate(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "1.2.0")

	avail, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if avail != nil {
		t.Fatalf("offered %s while already running it", avail.Version)
	}
}

// The tag style this repository uses must not read as an update to itself.
func TestCheckToleratesLeadingZeroTags(t *testing.T) {
	h := newHub(t)
	h.publish("v1.0.001", fakeELF())
	m := h.manager(t, "1.0.1")

	avail, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if avail != nil {
		t.Fatalf("v1.0.001 offered as an update to 1.0.1")
	}
}

func TestCheckRefusesToCompareDevBuilds(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "dev")

	_, err := m.Check(context.Background(), false)
	if err == nil {
		t.Fatal("a dev build was compared against a release")
	}
	if reasonOf(err) != ReasonUnorderable {
		t.Fatalf("reason = %q, want unorderable", reasonOf(err))
	}
}

// This is the failure the repository is in right now: a release exists but
// carries no files. It has to be named as such.
func TestStageExplainsReleaseWithoutAssets(t *testing.T) {
	h := newHub(t)
	h.releases = []Release{{Tag: "v1.0.001", PublishedAt: time.Now()}}
	m := h.manager(t, "1.0.0")

	_, err := m.Stage(context.Background(), "v1.0.001", "tester", false)
	if err == nil {
		t.Fatal("staging a release with no assets succeeded")
	}
	if reasonOf(err) != ReasonNoAssets {
		t.Fatalf("reason = %q, want no_assets", reasonOf(err))
	}
	if !strings.Contains(err.Error(), "no files attached") {
		t.Fatalf("unhelpful message: %v", err)
	}
}

func TestStageExplainsMissingArchitecture(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "1.1.0")
	m.goarch = "riscv64" // nothing was built for it

	_, err := m.Stage(context.Background(), "v1.2.0", "tester", false)
	if err == nil {
		t.Fatal("staging succeeded for an architecture with no build")
	}
	if reasonOf(err) != ReasonNoBuild {
		t.Fatalf("reason = %q, want no_build", reasonOf(err))
	}
	// The message has to say what the release does contain.
	if !strings.Contains(err.Error(), "revpd_1.2.0_linux_amd64.tar.gz") {
		t.Fatalf("message does not list the available builds: %v", err)
	}
}

func TestStageVerifiesAndParksTheBinary(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "1.1.0")

	staged, err := m.Stage(context.Background(), "v1.2.0", "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Version != "v1.2.0" || staged.StagedBy != "admin" {
		t.Fatalf("unexpected manifest: %+v", staged)
	}

	body, err := os.ReadFile(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, fakeELF()) {
		t.Fatal("the staged binary is not what was published")
	}

	sum := sha256.Sum256(body)
	if staged.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("the manifest hash does not match the staged file")
	}
	if st := m.State(); st.Phase != PhaseStaged {
		t.Fatalf("phase = %q, want staged", st.Phase)
	}
}

func TestStageRejectsATamperedArchive(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())

	// Swap the archive for a different one after the checksums were published,
	// which is what an interfering proxy or a compromised mirror looks like.
	h.assets["revpd_1.2.0_linux_amd64.tar.gz"] = tarGz(t, "revpd", []byte("malicious"))

	m := h.manager(t, "1.1.0")
	_, err := m.Stage(context.Background(), "v1.2.0", "admin", false)
	if err == nil {
		t.Fatal("a tampered archive was accepted")
	}
	if reasonOf(err) != ReasonCorrupt {
		t.Fatalf("reason = %q, want corrupt", reasonOf(err))
	}
	if _, statErr := os.Stat(m.stagedBin()); statErr == nil {
		t.Fatal("the tampered binary was left staged")
	}
}

func TestStageRefusesAReleaseWithoutChecksums(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF(), func(r *Release) {
		r.Assets = r.Assets[:1] // drop checksums.txt
	})

	m := h.manager(t, "1.1.0")
	if _, err := m.Stage(context.Background(), "v1.2.0", "admin", false); err == nil {
		t.Fatal("an unverifiable release was installed")
	}
}

func TestStageRejectsAForeignArchitecture(t *testing.T) {
	h := newHub(t)

	arm := fakeELF()
	arm[18] = 0xb7 // EM_AARCH64 in an archive named amd64
	h.publish("v1.2.0", arm)

	m := h.manager(t, "1.1.0")
	_, err := m.Stage(context.Background(), "v1.2.0", "admin", false)
	if err == nil {
		t.Fatal("a binary for another architecture was staged")
	}
	if !strings.Contains(err.Error(), "amd64") {
		t.Fatalf("message does not name this machine's architecture: %v", err)
	}
}

func TestRequestApplyWritesAMarkerTheApplierCanRead(t *testing.T) {
	h := newHub(t)
	h.publish("v1.2.0", fakeELF())
	m := h.manager(t, "1.1.0")

	if _, err := m.Stage(context.Background(), "v1.2.0", "admin", false); err != nil {
		t.Fatal(err)
	}
	if err := m.RequestApply("admin"); err != nil {
		t.Fatal(err)
	}

	req, err := readRequest(m.requestPath())
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != "v1.2.0" || req.SHA256 == "" {
		t.Fatalf("unusable request: %+v", req)
	}
	if st := m.State(); st.Phase != PhaseApplying {
		t.Fatalf("phase = %q, want applying", st.Phase)
	}
}

func TestRequestApplyNeedsSomethingStaged(t *testing.T) {
	h := newHub(t)
	m := h.manager(t, "1.1.0")
	if err := m.RequestApply("admin"); err == nil {
		t.Fatal("an empty staging directory was submitted for install")
	}
}

// The applier re-verifies rather than trusting the request, so a request that
// no longer matches what is staged must be refused.
func TestApplyRefusesAMismatchedRequest(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged")
	os.MkdirAll(staged, 0o755)

	os.WriteFile(filepath.Join(staged, "revpd"), fakeELF(), 0o755)
	writeJSON(t, filepath.Join(staged, "manifest.json"), Staged{Version: "v1.2.0", SHA256: "deadbeef"})
	writeJSON(t, filepath.Join(dir, "apply.request"), applyRequest{Version: "v1.2.0", SHA256: "deadbeef"})

	res, err := Apply(context.Background(), ApplyOptions{Dir: dir, Binary: filepath.Join(dir, "current")})
	if err == nil {
		t.Fatal("a request whose hash does not match the file was applied")
	}
	if res == nil || res.OK {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Message, "hash") {
		t.Fatalf("message does not explain the mismatch: %s", res.Message)
	}

	// The request must be cleared, or the path unit fires on it forever.
	if _, err := os.Stat(filepath.Join(dir, "apply.request")); err == nil {
		t.Fatal("the failed request was left in place")
	}
}

func TestApplyWithNothingRequested(t *testing.T) {
	if _, err := Apply(context.Background(), ApplyOptions{Dir: t.TempDir()}); err != ErrNoRequest {
		t.Fatalf("err = %v, want ErrNoRequest", err)
	}
}

// The service learns how an install went by reading what the applier left, so
// that handover has to work.
func TestManagerAbsorbsTheApplierResult(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Options{DataDir: dir, Version: "1.1.0", Repo: "o/r"})
	if err != nil {
		t.Fatal(err)
	}

	writeJSON(t, filepath.Join(m.Dir(), "result.json"), Result{
		Version: "v1.2.0", OK: true, Message: "Updated.", At: time.Now(),
	})

	st := m.State()
	if st.Last == nil || !st.Last.OK || st.Last.Version != "v1.2.0" {
		t.Fatalf("result not picked up: %+v", st.Last)
	}
	if _, err := os.Stat(filepath.Join(m.Dir(), "result.json")); err == nil {
		t.Fatal("the result was read but not consumed, so it will be reported forever")
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	m, err := NewManager(Options{DataDir: dir, Version: "1.1.0", Repo: "o/r"})
	if err != nil {
		t.Fatal(err)
	}
	m.update(func(s *State) {
		s.Available = &Available{Version: "v1.2.0"}
		s.Phase = PhaseDownloading // interrupted by the restart
	})

	again, err := NewManager(Options{DataDir: dir, Version: "1.1.0", Repo: "o/r"})
	if err != nil {
		t.Fatal(err)
	}
	st := again.State()
	if st.Available == nil || st.Available.Version != "v1.2.0" {
		t.Fatal("the pending update was forgotten across a restart")
	}
	if st.Phase != PhaseIdle {
		t.Fatalf("phase = %q — a download that died with the process was left mid-flight", st.Phase)
	}
}

func TestRateLimitIsReportedAsSuch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
		http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	c := &Client{Repo: "o/r", HTTP: srv.Client(), base: srv.URL + "/repos/"}
	_, err := c.Latest(context.Background(), false)
	if err == nil {
		t.Fatal("a rate limit was not reported as an error")
	}
	if reasonOf(err) != ReasonRateLimit {
		t.Fatalf("reason = %q, want rate_limit", reasonOf(err))
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("message does not say how to fix it: %v", err)
	}
}

func TestNetworkFailureNamesTheCause(t *testing.T) {
	c := &Client{Repo: "o/r", base: "http://127.0.0.1:1/repos/"}
	_, err := c.Latest(context.Background(), false)
	if err == nil {
		t.Fatal("connecting to a closed port succeeded")
	}
	if reasonOf(err) != ReasonNetwork {
		t.Fatalf("reason = %q, want network", reasonOf(err))
	}
}

/* --------------------------------------------------------------- helpers -- */

func reasonOf(err error) Reason {
	var f *Failure
	if errors.As(err, &f) {
		return f.Reason
	}
	return ""
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

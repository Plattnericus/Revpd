package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Phase is what the updater is doing right now, so the dashboard can show
// progress rather than a spinner that means nothing.
type Phase string

const (
	PhaseIdle        Phase = "idle"
	PhaseChecking    Phase = "checking"
	PhaseDownloading Phase = "downloading"
	PhaseVerifying   Phase = "verifying"
	PhaseStaged      Phase = "staged"   // verified and waiting for the applier
	PhaseApplying    Phase = "applying" // the privileged half has taken over
	PhaseFailed      Phase = "failed"
)

// Available describes a release that is newer than what is running.
type Available struct {
	Version     string    `json:"version"`
	Notes       string    `json:"notes"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Size        int64     `json:"size"`

	// AssetReady is false while the release exists but the build for this
	// machine has not been attached to it yet — the minutes between publishing
	// a release and its workflow finishing. The update is real, it just cannot
	// be installed this second, and offering a button that fails would be
	// worse than saying so.
	AssetReady bool `json:"asset_ready"`
}

// Staged is a downloaded, checksum-verified binary waiting to be installed.
type Staged struct {
	Version   string    `json:"version"`
	SHA256    string    `json:"sha256"`
	Path      string    `json:"path"`
	StagedAt  time.Time `json:"staged_at"`
	StagedBy  string    `json:"staged_by"`
	Automatic bool      `json:"automatic"`
}

// Result is what the privileged applier leaves behind. The service reads it
// after the restart to report how the last attempt actually went.
type Result struct {
	Version    string    `json:"version"`
	From       string    `json:"from"`
	OK         bool      `json:"ok"`
	Message    string    `json:"message"`
	RolledBack bool      `json:"rolled_back"`
	At         time.Time `json:"at"`
}

// State is the whole updater picture, persisted so it survives the restart
// that installing an update necessarily causes.
type State struct {
	Phase Phase `json:"phase"`

	LastCheck     time.Time `json:"last_check"`
	LastCheckErr  string    `json:"last_check_error,omitempty"`
	LastCheckKind Reason    `json:"last_check_reason,omitempty"`

	Available *Available `json:"available,omitempty"`
	Staged    *Staged    `json:"staged,omitempty"`
	Last      *Result    `json:"last_result,omitempty"`

	// Downloaded and Total drive the progress bar while PhaseDownloading.
	Downloaded int64 `json:"downloaded"`
	Total      int64 `json:"total"`
}

func loadState(dir string) State {
	var st State
	body, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return State{Phase: PhaseIdle}
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return State{Phase: PhaseIdle}
	}
	if st.Phase == "" {
		st.Phase = PhaseIdle
	}
	// A phase mid-flight cannot have survived a restart: whatever was running
	// died with the old process. Applying is the exception — that one is
	// meant to outlive us, and its outcome arrives in result.json.
	if st.Phase == PhaseChecking || st.Phase == PhaseDownloading || st.Phase == PhaseVerifying {
		st.Phase = PhaseIdle
	}
	return st
}

func saveState(dir string, st State) error {
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "state.json"), body, 0o640)
}

// writeFileAtomic never leaves a half-written file behind for the other half
// of the updater to read.
func writeFileAtomic(path string, body []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

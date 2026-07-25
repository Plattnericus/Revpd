package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/update"
)

// SettingAutoUpdate is where the dashboard toggle is kept. The value in
// revpd.yaml is the starting point; once an administrator has flipped the
// switch, their choice is what counts.
const SettingAutoUpdate = "update.auto_install"

// WithUpdates gives the API an updater. Without one the endpoints still answer,
// reporting that updating is not available here — which is the truth in a
// container, where the image is replaced rather than the binary.
func (s *Server) WithUpdates(m *update.Manager, version string) *Server {
	s.updates, s.version = m, version
	return s
}

/* --------------------------------------------------------------- status --- */

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	send(w, s.updateView(r.Context()))
}

func (s *Server) updateView(ctx context.Context) map[string]any {
	if s.updates == nil {
		return map[string]any{
			"supported": false,
			"reason":    "This gateway was not started with the updater enabled. In Docker, pull a new image instead.",
			"current":   s.version,
		}
	}

	st := s.updates.State()

	view := map[string]any{
		"supported":     true,
		"current":       s.updates.Current(),
		"repo":          s.updates.Repo(),
		"phase":         string(st.Phase),
		"auto_install":  s.autoInstallEnabled(ctx),
		"check_enabled": s.cfg.Update.Enabled,
		"prerelease":    s.cfg.Update.Prerelease,

		// Downloading and verifying is all this process can do on its own.
		// Without the privileged half nothing can actually be installed, and
		// saying so up front beats a button that quietly never finishes.
		"can_install": update.ApplierInstalled(),
	}

	if !st.LastCheck.IsZero() {
		view["last_check"] = st.LastCheck.UTC().Format(time.RFC3339)
	}
	if st.LastCheckErr != "" {
		view["error"] = st.LastCheckErr
		view["error_reason"] = string(st.LastCheckKind)
	}

	if a := st.Available; a != nil {
		view["available"] = map[string]any{
			"version":      a.Version,
			"notes":        a.Notes,
			"url":          a.URL,
			"published_at": a.PublishedAt.UTC().Format(time.RFC3339),
			"prerelease":   a.Prerelease,
			"size":         a.Size,
			"asset_ready":  a.AssetReady,
		}
	}
	if st.Staged != nil {
		view["staged"] = map[string]any{
			"version":   st.Staged.Version,
			"staged_at": st.Staged.StagedAt.UTC().Format(time.RFC3339),
		}
	}
	if st.Total > 0 {
		view["progress"] = map[string]any{"downloaded": st.Downloaded, "total": st.Total}
	}
	if l := st.Last; l != nil {
		view["last_result"] = map[string]any{
			"version":     l.Version,
			"from":        l.From,
			"ok":          l.OK,
			"message":     l.Message,
			"rolled_back": l.RolledBack,
			"at":          l.At.UTC().Format(time.RFC3339),
		}
	}
	return view
}

func (s *Server) autoInstallEnabled(ctx context.Context) bool {
	return s.db.BoolSetting(ctx, SettingAutoUpdate, s.cfg.Update.AutoInstall)
}

/* ---------------------------------------------------------------- check --- */

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		fail(w, http.StatusNotImplemented, "updating is not available in this deployment")
		return
	}

	// The API call is on a foreign network; do not let it outlive the request
	// budget the browser is willing to wait for.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	avail, err := s.updates.Check(ctx, s.cfg.Update.Prerelease)
	if err != nil {
		// Not a server error: the message explains what to do about it, and
		// the dashboard shows it verbatim.
		fail(w, http.StatusBadGateway, err.Error())
		return
	}

	s.audit(r, audit.Entry{
		Actor: userFrom(r.Context()).Username, Action: audit.ActionUpdateChecked,
		Object: versionOrNone(avail), SrcIP: s.clientIP(r).String(),
	})
	send(w, s.updateView(r.Context()))
}

func versionOrNone(a *update.Available) string {
	if a == nil {
		return "up to date"
	}
	return a.Version
}

/* -------------------------------------------------------------- install --- */

func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		fail(w, http.StatusNotImplemented, "updating is not available in this deployment")
		return
	}

	var req struct {
		Version string `json:"version"`
	}
	// An empty body means "whatever the last check found".
	if r.ContentLength > 0 && !decode(w, r, &req) {
		return
	}

	st := s.updates.State()
	if req.Version == "" {
		if st.Available == nil {
			fail(w, http.StatusBadRequest, "there is no newer release to install — check for one first")
			return
		}
		req.Version = st.Available.Version

		// Published, but its build has not been attached yet. Downloading now
		// would only fail, and the check that runs on a timer will pick it up
		// as soon as it lands.
		if !st.Available.AssetReady {
			fail(w, http.StatusConflict,
				"release "+req.Version+" is published but its build for this machine has not been attached yet. "+
					"That usually takes a couple of minutes after a release goes up — check again shortly.")
			return
		}
	}

	if !update.ApplierInstalled() {
		fail(w, http.StatusPreconditionFailed,
			"the privileged updater is not installed on this machine, so a downloaded update could not be applied. "+
				"Re-run install.sh to add it, or update from the command line with: sudo revpd update install")
		return
	}

	u := userFrom(r.Context())

	// Downloading takes as long as it takes. Detaching it from the request
	// keeps the browser from timing out mid-transfer and leaving the staging
	// directory half-populated.
	go s.stageAndApply(req.Version, u.Username)

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionUpdateStaged,
		Object: req.Version, SrcIP: s.clientIP(r).String(),
	})
	send(w, s.updateView(r.Context()))
}

// stageAndApply downloads, verifies and then asks the privileged half to
// install. Progress lands in the updater state, which the dashboard polls.
func (s *Server) stageAndApply(version, by string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	if _, err := s.updates.Stage(ctx, version, by, false); err != nil {
		slog.Error("staging the update failed", "version", version, "err", err)
		return
	}
	if err := s.updates.RequestApply(by); err != nil {
		slog.Error("could not hand the update to the applier", "version", version, "err", err)
	}
}

/* ------------------------------------------------------------- settings --- */

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutoInstall *bool `json:"auto_install"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.AutoInstall == nil {
		fail(w, http.StatusBadRequest, "nothing to change")
		return
	}

	u := userFrom(r.Context())
	if err := s.db.SetBoolSetting(r.Context(), SettingAutoUpdate, *req.AutoInstall, u.Username); err != nil {
		serverError(w, err)
		return
	}

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionSettingsUpdate, SrcIP: s.clientIP(r).String(),
		Detail: map[string]any{"auto_install": *req.AutoInstall},
	})
	send(w, s.updateView(r.Context()))
}

/* ----------------------------------------------------------- background --- */

// RunAutoUpdate checks for releases on a timer and installs them when the
// dashboard toggle says to.
//
// An update means a restart, which drops every live RDP session, so an
// automatic install waits for the gateway to be idle unless that was
// deliberately turned off.
func (s *Server) RunAutoUpdate(ctx context.Context) {
	if s.updates == nil || !s.cfg.Update.Enabled {
		return
	}

	every := s.cfg.Update.CheckInterval
	if every < 15*time.Minute {
		every = 15 * time.Minute
	}

	// A short delay first: at boot the network may not be up yet, and every
	// gateway installed from the same script would otherwise call GitHub at
	// the same moment after a power cut.
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(every)

		s.checkAndMaybeInstall(ctx)
	}
}

func (s *Server) checkAndMaybeInstall(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	avail, err := s.updates.Check(checkCtx, s.cfg.Update.Prerelease)
	cancel()

	if err != nil {
		var f *update.Failure
		if errors.As(err, &f) && f.Reason == update.ReasonUnorderable {
			// A hand-built binary. Saying this once an interval would be noise.
			slog.Debug("update check skipped", "reason", f.Message)
			return
		}
		slog.Warn("update check failed", "err", err)
		return
	}
	if avail == nil {
		return
	}

	slog.Info("a newer release is available", "version", avail.Version, "current", s.updates.Current())

	if !avail.AssetReady {
		// The release is up but its build has not landed. The next tick will
		// find it; nothing to do but wait.
		slog.Info("its build is not published yet, waiting for the next check", "version", avail.Version)
		return
	}

	if !s.autoInstallEnabled(ctx) {
		return // the dashboard will show it; a person decides
	}
	if !update.ApplierInstalled() {
		slog.Warn("automatic updates are on but the privileged updater is not installed",
			"version", avail.Version)
		return
	}

	if s.cfg.Update.OnlyWhenIdle {
		live, err := s.db.ListLiveSessions(ctx)
		if err == nil && len(live) > 0 {
			slog.Info("holding the update back, someone is connected",
				"version", avail.Version, "sessions", len(live))
			return
		}
	}

	slog.Info("installing update automatically", "version", avail.Version)
	s.stageAndApply(avail.Version, "auto-update")
}

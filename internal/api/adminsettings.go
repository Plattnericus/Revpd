package api

import (
	"context"
	"net/http"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/update"
)

/*
	The settings page.

	Two values are reported for every setting: what revpd.yaml and the
	environment say, and what is actually in force. They differ when somebody
	has changed one here, and showing both is what makes that reversible —
	"back to the file" is always an option, and nobody has to guess whether a
	value came from the installer or from a click last month.

	Saving validates the whole set against the real configuration rules before
	storing anything, so a rejected save changes nothing at all.
*/

// WithFileConfig records the configuration as it came from disk and the
// environment, before anything stored here was layered on top.
func (s *Server) WithFileConfig(c config.Config) *Server {
	s.fileCfg = c
	return s
}

type settingView struct {
	Key   string `json:"key"`
	Group string `json:"group"`
	Kind  string `json:"kind"`

	// Value is what will be in force: the file with every stored override
	// applied. This is what the form shows, because it is what was asked for.
	Value string `json:"value"`

	// Running is what this process actually loaded. It lags Value for anything
	// changed since the last start, which is exactly what Pending reports.
	Running string `json:"running"`

	// File is what revpd.yaml and the environment say on their own.
	File string `json:"file"`

	Min     int64    `json:"min,omitempty"`
	Max     int64    `json:"max,omitempty"`
	Restart bool     `json:"restart"`
	Warn    string   `json:"warn,omitempty"`
	Options []string `json:"options,omitempty"`

	// Pending means this value has been saved but the running process is still
	// using the old one. Showing the saved value with a marker beats showing
	// the old one, which reads as though the save was lost.
	Pending bool `json:"pending"`

	// Overridden means the value came from here rather than the file.
	Overridden bool   `json:"overridden"`
	ChangedBy  string `json:"changed_by,omitempty"`
	ChangedAt  string `json:"changed_at,omitempty"`
}

func (s *Server) handleSettingsSchema(w http.ResponseWriter, r *http.Request) {
	meta, err := s.db.SettingsWithMeta(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	// What the gateway would run with if it started now. Computed once, from
	// the file plus everything stored, rather than per setting.
	wanted := s.wantedConfig(r.Context())

	out := make([]settingView, 0, len(config.Registry()))
	for _, def := range config.Registry() {
		value, running := def.Value(wanted), def.Value(s.cfg)

		v := settingView{
			Key:     def.Key,
			Group:   string(def.Group),
			Kind:    string(def.Kind),
			Value:   value,
			Running: running,
			File:    def.Value(s.fileCfg),
			Min:     def.Min,
			Max:     def.Max,
			Restart: def.NeedsRestart(),
			Warn:    def.Warn,
			Options: def.Options,
			Pending: def.NeedsRestart() && value != running,
		}
		if m, ok := meta[def.Key]; ok {
			v.Overridden = true
			v.ChangedBy = m.UpdatedBy
			if m.UpdatedAt > 0 {
				v.ChangedAt = time.Unix(m.UpdatedAt, 0).UTC().Format(time.RFC3339)
			}
		}
		out = append(out, v)
	}

	groups := make([]string, 0, len(config.Groups))
	for _, g := range config.Groups {
		groups = append(groups, string(g))
	}

	send(w, map[string]any{
		"groups":   groups,
		"settings": out,

		// What the gateway is doing right now, which is not always what was
		// asked for: the portal moves when its port is taken.
		"runtime": map[string]any{
			"portal":         s.portalAddr,
			"portal_url":     config.PortalURL(s.cfg.Web.Hostname, s.portalAddr),
			"gateway":        s.gatewayAddr(r.Context()),
			"restart_needed": s.restartPending(r.Context()),
			"can_restart":    update.ApplierInstalled(),

			// How the same gateway looks from the internet, which is the
			// address worth showing on a page that is often open over the LAN.
			"network": s.networkView(r.Context(), nil),
		},
	})
}

// handleSettingsSave validates and stores a set of changes.
func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Values map[string]string `json:"values"`
		// Reset hands the listed keys back to revpd.yaml.
		Reset []string `json:"reset"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Values) == 0 && len(req.Reset) == 0 {
		fail(w, http.StatusBadRequest, "nothing to change")
		return
	}

	stored, err := s.db.AllSettings(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	// Work out what the world would look like afterwards, and judge that —
	// not the individual change. Settings constrain each other, and a pair
	// that is only valid together has to be allowed to arrive together.
	wanted := map[string]string{}
	for k, v := range stored {
		wanted[k] = v
	}
	for _, k := range req.Reset {
		delete(wanted, k)
	}
	for k, v := range req.Values {
		if _, ok := config.Lookup(k); !ok {
			fail(w, http.StatusBadRequest, "there is no setting called "+k)
			return
		}
		wanted[k] = v
	}

	if _, _, err := config.Apply(s.fileCfg, wanted); err != nil {
		// The message comes from the same validation that guards the file, so
		// it already explains itself. Passing it through verbatim beats
		// paraphrasing it into something vaguer.
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	u := userFrom(r.Context())
	for _, k := range req.Reset {
		if err := s.db.ClearSetting(r.Context(), k); err != nil {
			serverError(w, err)
			return
		}
	}
	if len(req.Values) > 0 {
		if err := s.db.ReplaceSettings(r.Context(), req.Values, u.Username); err != nil {
			serverError(w, err)
			return
		}
	}

	// The public host is only ever displayed or written into a .rdp file, so a
	// change to it can take hold now instead of waiting for a restart that
	// would drop every open desktop session.
	applied := s.wantedConfig(r.Context())
	if s.public != nil {
		s.public.SetHost(applied.PublicHost())
	}

	// Same reasoning, and it matters more here: the destination is what people
	// get wrong first, and correcting it should not cost anybody their session.
	if s.notifier != nil {
		s.notifier.Configure(applied.NotifyConfig())
	}

	changed := make([]string, 0, len(req.Values)+len(req.Reset))
	for k := range req.Values {
		changed = append(changed, k)
	}
	changed = append(changed, req.Reset...)

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionSettingsUpdate, SrcIP: s.clientIP(r).String(),
		Detail: map[string]any{"keys": changed},
	})

	s.handleSettingsSchema(w, r)
}

// wantedConfig is the file with every stored override applied: what the
// gateway would run with if it started right now.
//
// A stored set that no longer validates falls back to the running
// configuration rather than an error. It can only happen if the file changed
// underneath the overrides, and a settings page that refuses to render is a
// settings page nobody can use to fix it.
func (s *Server) wantedConfig(ctx context.Context) config.Config {
	stored, err := s.db.AllSettings(ctx)
	if err != nil {
		return s.cfg
	}
	wanted, _, err := config.Apply(s.fileCfg, stored)
	if err != nil {
		return s.cfg
	}
	return wanted
}

// restartPending reports whether anything saved differs from what the running
// process actually loaded. That is the honest test: comparing against the file
// would flag settings that were already applied at the last start.
func (s *Server) restartPending(ctx context.Context) bool {
	wanted := s.wantedConfig(ctx)

	for _, def := range config.Registry() {
		if !def.NeedsRestart() {
			continue
		}
		if def.Value(wanted) != def.Value(s.cfg) {
			return true
		}
	}
	return false
}

/* -------------------------------------------------------------- restart --- */

// handleRestart asks the privileged helper to restart the service.
//
// The service cannot restart itself: it runs as an unprivileged account, and
// systemd would refuse. The same root-owned unit that installs updates does
// this, for the same reason and through the same request directory.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		fail(w, http.StatusNotImplemented,
			"this deployment cannot restart itself — restart the container or the service by hand")
		return
	}
	if !update.ApplierInstalled() {
		fail(w, http.StatusPreconditionFailed,
			"the privileged helper is not installed, so the service cannot be restarted from here. "+
				"Run: sudo systemctl restart revpd")
		return
	}

	u := userFrom(r.Context())

	// Restarting drops every open desktop session, so say how many rather than
	// letting someone find out from the people who were using them.
	live, _ := s.db.ListLiveSessions(r.Context())

	if err := s.updates.RequestRestart(u.Username); err != nil {
		serverError(w, err)
		return
	}

	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionSettingsUpdate, SrcIP: s.clientIP(r).String(),
		Detail: map[string]any{"restart": true, "sessions_dropped": len(live)},
	})

	send(w, map[string]any{"ok": true, "sessions_dropped": len(live)})
}

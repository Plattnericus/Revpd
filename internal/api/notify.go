package api

import (
	"net/http"

	"github.com/plattnericus/revpd/internal/notify"
)

// WithNotifier hands over the thing that sends messages out, so a changed
// destination applies on save and the settings page can try it.
func (s *Server) WithNotifier(n *notify.Notifier) *Server {
	s.notifier = n
	return s
}

/*
handleNotifyTest sends one real message to whatever is configured.

Real, not simulated: the failures worth catching here are a topic name with a
typo in it, a webhook that was revoked, and a firewall that does not let this
machine out. None of those show up in a dry run, and all of them are otherwise
discovered by an alert that never arrives.

The saved settings are used rather than anything posted with the request, so
this cannot be turned into a way to make the gateway fetch an arbitrary URL.
*/
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		fail(w, http.StatusNotImplemented, "notifications are not available in this deployment")
		return
	}

	cfg := s.wantedConfig(r.Context()).Notify
	if !cfg.Enabled {
		fail(w, http.StatusPreconditionFailed, "notifications are switched off — turn them on and save first")
		return
	}

	if err := s.notifier.Test(r.Context()); err != nil {
		// The reason comes from the far end and is the useful half of the
		// answer. It never contains the URL, which is why it can be shown.
		fail(w, http.StatusBadGateway, "the message could not be delivered: "+err.Error())
		return
	}

	send(w, map[string]any{"ok": true})
}

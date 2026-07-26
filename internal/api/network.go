package api

import (
	"context"
	"net/http"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/netcheck"
)

/*
	"Where do I point Remote Desktop, and does it work from outside?"

	Two questions the gateway cannot answer from its own sockets. Behind a
	router they only ever see the LAN, so the address people type and the port
	the router forwards both have to come from somewhere else — an operator who
	typed a domain, or a machine on the far side of the NAT that was asked.

	The answer is a display value and nothing more. No grant, no token and no
	forwarding decision reads it, which is what makes it safe to take part of
	it from a stranger.
*/

// WithPublic attaches the public-address service. Nil is fine and leaves the
// gateway working off its configured hostname alone.
func (s *Server) WithPublic(p *netcheck.Service) *Server {
	s.public = p
	return s
}

type endpointView struct {
	// Address is what to type: host, plus the port when it is not the one the
	// client would have assumed anyway.
	Address string `json:"address"`

	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`

	// Listen is the local socket this is forwarded to, so a port-forward rule
	// can be read straight off the page.
	Listen string `json:"listen,omitempty"`

	// Forwarded is true when the outside port and the inside port differ,
	// which is the case that needs explaining.
	Forwarded bool `json:"forwarded"`
}

type networkView struct {
	netcheck.State

	RDP    endpointView `json:"rdp"`
	Portal endpointView `json:"portal"`

	// PortalURL is the same thing as a link, since that one is clickable.
	PortalURL string `json:"portal_url,omitempty"`

	// Detecting reports whether the lookup is switched on at all, so the
	// interface can say "off" rather than showing an empty result as failure.
	Detecting bool `json:"detecting"`

	// Reach holds the result of the last knock on our own address, if anyone
	// has asked for one. Absent until they do — it is not run on a timer.
	Reach *reachView `json:"reach,omitempty"`
}

type reachView struct {
	RDP    netcheck.ProbeResult `json:"rdp"`
	Portal netcheck.ProbeResult `json:"portal"`

	// Confirmed is true only when both were accepted. A failure proves very
	// little, since most routers refuse to loop a connection back inside.
	Confirmed bool      `json:"confirmed"`
	CheckedAt time.Time `json:"checked_at"`
}

// handleNetwork reports how the gateway is reached from outside.
func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	send(w, s.networkView(r.Context(), nil))
}

// handleNetworkCheck looks again, on request.
//
// Detection is rate-limited inside the service, so this button cannot be
// leaned on to hammer somebody else's endpoint.
func (s *Server) handleNetworkCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		// Probe knocks on our own public address as well as re-detecting it.
		// Separate because it opens connections rather than just asking a
		// question, and because it takes a few seconds when it fails.
		Probe bool `json:"probe"`
	}
	if r.ContentLength > 0 && !decode(w, r, &req) {
		return
	}

	// Neither the lookup nor the knock should outlive what a browser is
	// willing to wait for.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if s.public != nil {
		s.public.Refresh(ctx)
	}

	var reach *reachView
	if req.Probe {
		reach = s.probe(ctx)
	}

	u := userFrom(r.Context())
	s.audit(r, audit.Entry{
		Actor: u.Username, Action: audit.ActionSettingsUpdate, SrcIP: s.clientIP(r).String(),
		Detail: map[string]any{"public_address_check": true, "probe": req.Probe},
	})

	send(w, s.networkView(ctx, reach))
}

// probe knocks on our own public address.
//
// It takes no parameters from the request: the host and both ports come from
// the configuration, so this cannot be pointed anywhere else. Without that it
// would be a way to make the gateway open connections to arbitrary addresses
// on somebody's behalf.
func (s *Server) probe(ctx context.Context) *reachView {
	cfg := s.wantedConfig(ctx)
	host := s.publicHost(cfg)

	rdp := netcheck.Probe(ctx, host, cfg.PublicRDPPort(), 5*time.Second)
	portal := netcheck.Probe(ctx, host, cfg.PublicPortalPort(), 5*time.Second)

	return &reachView{
		RDP:       rdp,
		Portal:    portal,
		Confirmed: rdp.Confirmed() && portal.Confirmed(),
		CheckedAt: time.Now().UTC(),
	}
}

// networkView assembles the whole picture from the configuration that would be
// in force now — not the snapshot this process started with.
//
// That is what lets a changed domain or forwarded port show up the moment it
// is saved. It can afford to: nothing here binds a socket or signs anything,
// so there is no running state for a new value to disagree with.
func (s *Server) networkView(ctx context.Context, reach *reachView) networkView {
	cfg := s.wantedConfig(ctx)
	host := s.publicHost(cfg)

	state := netcheck.State{Host: host, Configured: cfg.Public.Host}
	if s.public != nil {
		state = s.public.Current()

		// The service knows what was detected; the configuration knows what an
		// operator has just typed. On the settings page the second is newer.
		state.Configured = cfg.Public.Host
		state.Host = host
		if cfg.Public.Host != "" {
			state.Source = netcheck.SourceConfigured
		} else if state.Detected != "" {
			state.Source = state.DetectedSource
		}
	}
	if host != "" && state.Source == "" {
		// Falling back to web.hostname, which an operator also chose.
		state.Source = netcheck.SourceConfigured
	}

	rdpPort, portalPort := cfg.PublicRDPPort(), cfg.PublicPortalPort()

	return networkView{
		State:     state,
		Detecting: cfg.Public.Detect,
		RDP: endpointView{
			Address:   netcheck.JoinHostPort(host, rdpPort, 3389),
			Host:      host,
			Port:      rdpPort,
			Listen:    cfg.Relay.Listen,
			Forwarded: rdpPort != cfg.RelayPort(),
		},
		Portal: endpointView{
			Address:   netcheck.JoinHostPort(host, portalPort, 443),
			Host:      host,
			Port:      portalPort,
			Listen:    s.portalAddr,
			Forwarded: portalPort != cfg.PortalPort(),
		},
		PortalURL: publicPortalURL(host, portalPort),
		Reach:     reach,
	}
}

// publicHost is the address the outside world uses, preferring what has been
// configured and falling back to what was detected.
func (s *Server) publicHost(cfg config.Config) string {
	if h := cfg.PublicHost(); h != "" {
		return h
	}
	if s.public != nil {
		if d := s.public.Current().Detected; d != "" {
			return d
		}
	}
	// Better a name that is at least internally consistent than an empty
	// field where the address goes.
	return cfg.Web.Hostname
}

// publicGateway is what somebody types into Remote Desktop, from the
// configuration in force now.
func (s *Server) publicGateway(ctx context.Context) string {
	cfg := s.wantedConfig(ctx)
	return netcheck.JoinHostPort(s.publicHost(cfg), cfg.PublicRDPPort(), 3389)
}

func publicPortalURL(host string, port int) string {
	if host == "" {
		return ""
	}
	return "https://" + netcheck.JoinHostPort(host, port, 443)
}

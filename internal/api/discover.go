package api

import (
	"context"
	"net/http"
	"time"

	"github.com/plattnericus/revpd/internal/discover"
)

/*
	Finding machines to add.

	Typing an IP address and a MAC by hand is where adding a target goes wrong:
	the address is easy and the hardware address is not, and a target saved
	without one looks fine until the machine sleeps and never comes back.

	So the gateway looks for itself. It cannot do this the way a scanner
	normally would — the unit grants no CAP_NET_RAW and no packet sockets, so
	there is no ping sweep and no ARP request to be had. Ordinary TCP
	connections turn out to be enough: they reveal which machines are there,
	the greeting on port 22 names the distribution, an RDP negotiation
	identifies Windows, and the kernel learns each hardware address as a side
	effect of connecting.
*/

// handleDiscoverRanges offers the networks this machine is attached to, so
// nobody has to work out what their own subnet is.
func (s *Server) handleDiscoverRanges(w http.ResponseWriter, r *http.Request) {
	ranges, err := discover.LocalRanges()
	if err != nil {
		serverError(w, err)
		return
	}

	send(w, map[string]any{
		"ranges": ranges,
		"limit":  discover.MaxHosts,

		// Whether the richer, version-based detection is active. Decided once
		// here rather than guessed from the results: a network with only
		// unremarkable devices on it would otherwise look the same either way.
		"nmap_available": discover.NmapAvailable(),
	})
}

// handleDiscoverScan sweeps a network.
func (s *Server) handleDiscoverScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.CIDR == "" {
		fail(w, http.StatusBadRequest, "no network to scan — pick one of the ranges this machine is on")
		return
	}

	// A sweep of a /24 finishes in a few seconds. The cap is here so a request
	// cannot be left hanging if something on the network swallows connections
	// instead of refusing them.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	hosts, err := discover.Scanner{}.Sweep(ctx, req.CIDR)
	if err != nil {
		// The refusals — a public range, a range too large — explain themselves
		// and are the caller's fault, not the server's.
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	send(w, map[string]any{
		"hosts": hosts,
		"known": s.knownAddresses(r.Context()),
	})
}

// handleDiscoverHost examines one address that somebody typed.
func (s *Server) handleDiscoverHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if !decode(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	host, err := discover.Scanner{}.Probe(ctx, req.IP)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	send(w, map[string]any{
		"hosts": []*discover.Host{host},
		"known": s.knownAddresses(r.Context()),
	})
}

// knownAddresses are the machines already saved, so the results can mark them
// rather than offering to add the same one twice.
func (s *Server) knownAddresses(ctx context.Context) []string {
	targets, err := s.db.ListTargets(ctx)
	if err != nil {
		return []string{}
	}

	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.IP != "" {
			out = append(out, t.IP)
		}
	}
	return out
}

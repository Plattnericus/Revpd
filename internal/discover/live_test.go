package discover

import (
	"context"
	"os"
	"testing"
	"time"
)

/*
	Against a real machine.

	Skipped unless REVPD_LIVE_HOST names one, because a test that reaches out
	to the network has no business running on somebody else's build server.
	When it does run it is the only check here that exercises the whole thing
	end to end: a real stack, a real ARP table, a real RDP server.

	    REVPD_LIVE_HOST=192.168.178.250 go test ./internal/discover/ -run Live -v
*/

func TestLiveProbe(t *testing.T) {
	host := os.Getenv("REVPD_LIVE_HOST")
	if host == "" {
		t.Skip("set REVPD_LIVE_HOST to probe a real machine")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h, err := Scanner{}.Probe(ctx, host)
	if err != nil {
		t.Fatalf("probing %s failed: %v", host, err)
	}

	t.Logf("ip         %s", h.IP)
	t.Logf("hostname   %s", orDash(h.Hostname))
	t.Logf("mac        %s", orDash(h.MAC))
	t.Logf("open       %v", h.OpenPorts)
	t.Logf("os         %s %s (%s)", h.OS, h.Distro, h.Confidence)
	t.Logf("suggested  %v", h.Suggested)
	t.Logf("wakeable   %v", h.Wakeable)
	for _, w := range h.Why {
		t.Logf("           - %s", w)
	}

	if len(h.OpenPorts) == 0 {
		t.Errorf("%s answered nothing — it is off, or a firewall is in the way", host)
	}

	// The hardware address is the whole point: without it the machine can be
	// reached while awake and never woken.
	if !h.Wakeable {
		t.Errorf("no hardware address for %s, so Wake-on-LAN could not reach it", host)
	}
}

func TestLiveSweep(t *testing.T) {
	cidr := os.Getenv("REVPD_LIVE_CIDR")
	if cidr == "" {
		t.Skip("set REVPD_LIVE_CIDR to sweep a real network")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	start := time.Now()
	hosts, err := Scanner{}.Sweep(ctx, cidr)
	if err != nil {
		t.Fatalf("sweeping %s failed: %v", cidr, err)
	}

	t.Logf("%d machines in %s", len(hosts), time.Since(start).Round(time.Millisecond))
	for _, h := range hosts {
		t.Logf("  %-15s %-17s %-22s %-8s %v",
			h.IP, orDash(h.MAC), orDash(h.Hostname), h.OS, h.OpenPorts)
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

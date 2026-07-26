package discover

import (
	"sort"
	"strings"
)

/*
	Working out what a machine is, from what it is willing to say.

	Nothing here needs privileges. Proper fingerprinting — the kind nmap does
	with -O — reads the shape of the TCP/IP stack itself, which means crafting
	packets, which means a raw socket, which means CAP_NET_RAW. This service
	runs without it on purpose, so the evidence has to come from what the
	machine answers on ordinary connections.

	That turns out to be plenty. An SSH greeting names the distribution
	outright on Debian and Ubuntu; a Windows box answers an RDP negotiation and
	almost nothing else does. Where the evidence is thinner the guess is
	reported as thinner, rather than dressed up.
*/

// OS is the family a machine belongs to.
type OS string

const (
	OSWindows OS = "windows"
	OSLinux   OS = "linux"
	OSMac     OS = "macos"
	OSUnknown OS = "unknown"
)

// Confidence is how much the guess is worth.
type Confidence string

const (
	High   Confidence = "high"   // the machine said so
	Medium Confidence = "medium" // a combination that is rarely anything else
	Low    Confidence = "low"    // a hint, no more
)

// Signals is what a probe managed to collect.
type Signals struct {
	// OpenPorts that answered a connection.
	OpenPorts []int

	// SSHBanner is the greeting from port 22, if it gave one.
	SSHBanner string

	// RDPAccepted means port 3389 answered an X.224 connection request the way
	// a Remote Desktop server does.
	RDPAccepted bool

	// Hostname from reverse DNS, if any.
	Hostname string
}

// Guess is the conclusion, with the reasons that led to it.
type Guess struct {
	OS         OS         `json:"os"`
	Distro     string     `json:"distro,omitempty"`
	Confidence Confidence `json:"confidence"`

	// Why lists the evidence in plain words, so a wrong guess can be argued
	// with rather than just overruled.
	Why []string `json:"why"`
}

// Identify turns collected signals into a conclusion.
func Identify(s Signals) Guess {
	g := Guess{OS: OSUnknown, Confidence: Low}

	// The SSH greeting is the strongest evidence there is, because on the
	// distributions people actually run it names itself:
	//   SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
	if banner := strings.TrimSpace(s.SSHBanner); banner != "" {
		g.OS = OSLinux
		g.Confidence = Medium
		g.Why = append(g.Why, "answers SSH: "+trim(banner, 60))

		lower := strings.ToLower(banner)
		switch {
		case strings.Contains(lower, "raspbian"):
			g.Distro, g.Confidence = "Raspberry Pi OS", High
		case strings.Contains(lower, "ubuntu"):
			g.Distro, g.Confidence = "Ubuntu", High
		case strings.Contains(lower, "debian"):
			g.Distro, g.Confidence = "Debian", High
		case strings.Contains(lower, "freebsd"):
			g.Distro, g.Confidence = "FreeBSD", High
		case strings.Contains(lower, "windows"):
			// OpenSSH ships with Windows now and says so.
			g.OS, g.Distro, g.Confidence = OSWindows, "Windows", High
			g.Why = append(g.Why, "the SSH greeting names Windows")
		case strings.Contains(lower, "_for_windows"):
			g.OS, g.Distro, g.Confidence = OSWindows, "Windows", High
		}

		if g.Distro != "" && g.OS == OSLinux {
			g.Why = append(g.Why, "the greeting names "+g.Distro)
		}
	}

	// An RDP server that completes the negotiation is a Windows machine, or
	// something impersonating one closely enough that it will behave like one.
	if s.RDPAccepted {
		g.OS = OSWindows
		g.Confidence = High
		g.Why = append(g.Why, "answers a Remote Desktop negotiation on 3389")
		if g.Distro == "" || g.Distro == "Debian" || g.Distro == "Ubuntu" {
			// SSH said Linux and RDP said Windows. xrdp on Linux does exactly
			// this, and it is worth being honest that the two disagree.
			if g.Distro != "" {
				g.Why = append(g.Why, "but SSH says "+g.Distro+" — probably xrdp")
				g.OS = OSLinux
				g.Confidence = Medium
			} else {
				g.Distro = "Windows"
			}
		}
	}

	open := portSet(s.OpenPorts)

	// Windows without RDP reachable: the file-sharing and management ports
	// together are not a combination anything else offers.
	if g.OS == OSUnknown {
		switch {
		case open[5985] || open[5986]:
			g.OS, g.Distro, g.Confidence = OSWindows, "Windows", High
			g.Why = append(g.Why, "answers on the Windows remote-management port")
		case open[445] && open[139]:
			g.OS, g.Distro, g.Confidence = OSWindows, "Windows", Medium
			g.Why = append(g.Why, "answers on the Windows file-sharing ports")
		case open[3389]:
			g.OS, g.Distro, g.Confidence = OSWindows, "Windows", Medium
			g.Why = append(g.Why, "port 3389 is open")
		case open[548] || open[88] && open[445]:
			g.OS, g.Confidence = OSMac, Low
			g.Why = append(g.Why, "answers on ports macOS file sharing uses")
		}
	}

	// A machine that is up but says nothing recognisable is still worth
	// listing: it may simply have a firewall in front of everything.
	if len(g.Why) == 0 && len(s.OpenPorts) > 0 {
		g.Why = append(g.Why, "answered on "+joinPorts(s.OpenPorts)+" but did not identify itself")
	}

	return g
}

// CanRDP reports whether this machine looks like something worth adding as a
// target: it either speaks RDP now, or has the port open.
func (g Guess) CanRDP(s Signals) bool {
	return s.RDPAccepted || portSet(s.OpenPorts)[3389]
}

func portSet(ports []int) map[int]bool {
	out := make(map[int]bool, len(ports))
	for _, p := range ports {
		out[p] = true
	}
	return out
}

func joinPorts(ports []int) string {
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)

	parts := make([]string, 0, len(sorted))
	for _, p := range sorted {
		parts = append(parts, itoa(p))
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

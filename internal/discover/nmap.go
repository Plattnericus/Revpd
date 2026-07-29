package discover

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
	nmap, used the one way this process is allowed to use anything.

	Real OS fingerprinting — nmap's -O — reads the shape of the TCP/IP stack
	itself: initial TTL, window size, the order of TCP options in a crafted
	SYN. Getting at any of that means a raw socket, which means CAP_NET_RAW,
	which the unit does not grant and is not going to start granting for this.
	-sS, the half-open SYN scan, needs the same thing and is refused for the
	same reason. Both stay off, always, no matter what is asked for — there is
	no flag or setting anywhere that turns them back on.

	What nmap's version detection (-sV) does needs none of that: it connects
	the way anything else does and reads what the service says back. That is
	exactly the same category of information internal/discover/fingerprint.go
	already collects from an SSH banner and an RDP negotiation, just with a
	deeper library of probes and a wider one of matches — nmap recognises
	"Microsoft Terminal Services" on 3389, the SMB dialect a file share
	answers with, and the flavour of RPC endpoint mapper that only Windows
	runs. Several of its service signatures even carry an ostype field for
	exactly this reason, filled in from a version string, never from a raw
	packet.

	So nmap is asked for exactly that, and nothing else: -sT -sV -Pn, a plain
	TCP connect scan with version probing, host discovery skipped because the
	native sweep already proved these addresses answer something. If the
	binary is not on PATH — the common case, since nothing here requires it —
	every one of these functions returns cleanly having done nothing, and the
	sweep is exactly as good as it was before this file existed.

	And it can only add to the native guess, never take from it: an RDP
	negotiation that actually completed outranks a version-probe string every
	time, because it is the protocol itself answering rather than a banner
	nmap's database happened to recognise.
*/

// nmapPath is where nmap was found, resolved once per process rather than
// searched on every sweep. Empty means it is not installed, which is the
// ordinary case and not a failure of anything.
var nmapPath = sync.OnceValue(func() string {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return ""
	}
	return path
})

// NmapAvailable reports whether nmap was found on PATH, so the discovery
// screen can say plainly whether the richer detection is active rather than
// a scan quietly looking the same either way.
func NmapAvailable() bool { return nmapPath() != "" }

// enrichWithNmap adds service and version evidence to hosts nmap can still
// tell us more about. It runs once per sweep, against exactly the addresses
// the native probe already found — never a whole /24 — and only touches
// ports already known to answer something.
//
// A failure here — nmap crashes, times out, is not installed after all — is
// swallowed. The native result is already correct on its own; this can only
// improve it, never make it worse, and a scan must never fail because an
// optional enhancement did.
func (s Scanner) enrichWithNmap(ctx context.Context, hosts []Host) {
	bin := nmapPath()
	if bin == "" || len(hosts) == 0 {
		return
	}

	targets := make([]string, 0, len(hosts))
	portSet := map[int]bool{}
	for _, h := range hosts {
		if addr, err := netip.ParseAddr(h.IP); err == nil {
			targets = append(targets, addr.String())
		}
		for _, p := range h.OpenPorts {
			portSet[p] = true
		}
	}
	if len(targets) == 0 || len(portSet) == 0 {
		return
	}

	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	// A generous but bounded budget: version probing several hosts on a
	// handful of ports normally takes a few seconds, and the caller's own
	// context still cuts this off earlier if the whole sweep is out of time.
	nctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	results, err := runNmap(nctx, bin, targets, ports)
	if err != nil {
		return
	}

	for i := range hosts {
		if r, ok := results[hosts[i].IP]; ok {
			refineWithNmap(&hosts[i], r.services)
		}
	}
}

/* -------------------------------------------------------------- process --- */

type nmapService struct {
	Port      int
	Name      string
	Product   string
	Version   string
	ExtraInfo string
	OSType    string
}

type nmapHostResult struct {
	services []nmapService
}

// runNmap invokes nmap as a plain, unprivileged TCP client and parses its XML
// report. The argument list is fixed and never grows a flag from anywhere
// else — targets and ports are the only variables, and both are addresses and
// numbers this package already validated, never a string a caller typed
// straight into a shell.
func runNmap(ctx context.Context, bin string, targets []string, ports []int) (map[string]nmapHostResult, error) {
	if len(targets) == 0 || len(ports) == 0 {
		return nil, errors.New("nothing to scan")
	}

	args := []string{
		"-sT",             // TCP connect scan: ordinary connect(), no raw socket
		"-sV",             // version detection: reads what the service says back
		"--version-light", // the quick probe set — this is an enrichment, not a census
		"-Pn",             // skip host discovery; the native sweep already proved these are up
		"-p", joinPorts(ports),
		"-oX", "-", // XML to stdout, nothing written to disk
		"-T4",
	}
	args = append(args, targets...)

	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap: %w: %s", err, strings.TrimSpace(errOut.String()))
	}

	return parseNmapXML(out.Bytes())
}

/* ------------------------------------------------------------------ xml --- */

type nmapRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Addresses []xmlAddress `xml:"address"`
	Ports     xmlPorts     `xml:"ports"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	PortID  string     `xml:"portid,attr"`
	State   xmlState   `xml:"state"`
	Service xmlService `xml:"service"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
}

// parseNmapXML reads exactly the fields refineWithNmap can use and ignores
// everything else in the report — nmap's schema carries far more than a
// version string and a guessed OS family, none of which this needs.
func parseNmapXML(body []byte) (map[string]nmapHostResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(body, &run); err != nil {
		return nil, fmt.Errorf("parse nmap report: %w", err)
	}

	out := make(map[string]nmapHostResult, len(run.Hosts))
	for _, h := range run.Hosts {
		var ip string
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		var services []nmapService
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			port, err := atoiStrict(p.PortID)
			if err != nil {
				continue
			}
			svc := p.Service
			if svc.Name == "" && svc.Product == "" && svc.OSType == "" {
				continue // version detection found nothing usable on this port
			}
			services = append(services, nmapService{
				Port:      port,
				Name:      svc.Name,
				Product:   svc.Product,
				Version:   svc.Version,
				ExtraInfo: svc.ExtraInfo,
				OSType:    svc.OSType,
			})
		}
		if len(services) > 0 {
			out[ip] = nmapHostResult{services: services}
		}
	}
	return out, nil
}

func atoiStrict(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q is not a number", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

/* -------------------------------------------------------------- fusion --- */

// confidenceRank orders confidence so a fresh guess can be compared against
// the one already on the host, and only takes over when it is genuinely
// stronger evidence.
func confidenceRank(c Confidence) int {
	switch c {
	case High:
		return 2
	case Medium:
		return 1
	default:
		return 0
	}
}

// refineWithNmap folds one host's nmap evidence into the guess the native
// probe already made. It only ever upgrades: replaces OSUnknown outright, and
// otherwise only overwrites a weaker confidence than the one it is offering.
func refineWithNmap(h *Host, services []nmapService) {
	for _, svc := range services {
		os, distro, conf, reason := nmapGuess(svc)
		if reason != "" {
			h.Why = append(h.Why, reason)
		}
		if os == OSUnknown {
			continue
		}
		if h.OS == OSUnknown || confidenceRank(conf) > confidenceRank(h.Confidence) {
			h.OS, h.Confidence = os, conf
			if distro != "" {
				h.Distro = distro
			}
		}
	}
}

// nmapGuess reads one service's version-detection result the way
// fingerprint.go reads an SSH banner: for what it says about itself, never
// for the shape of the packets that carried it.
func nmapGuess(svc nmapService) (os OS, distro string, confidence Confidence, reason string) {
	lower := strings.ToLower(svc.Product + " " + svc.ExtraInfo + " " + svc.Version)

	// ostype comes from nmap's own probe-to-OS table, filled in per signature
	// match — it is nmap naming the family the way an SSH banner names a
	// distribution, not a TCP/IP stack guess.
	switch strings.ToLower(svc.OSType) {
	case "windows":
		return OSWindows, windowsVersionFrom(lower), High,
			fmt.Sprintf("nmap: port %d looks like Windows (%s)", svc.Port, firstNonEmpty(svc.Product, svc.Name))
	case "linux":
		return OSLinux, "", Medium,
			fmt.Sprintf("nmap: port %d looks like Linux (%s)", svc.Port, firstNonEmpty(svc.Product, svc.Name))
	case "mac os x", "macos":
		return OSMac, "", Medium,
			fmt.Sprintf("nmap: port %d looks like macOS (%s)", svc.Port, firstNonEmpty(svc.Product, svc.Name))
	}

	// Samba serves the same ports a real Windows file share does, and
	// answers with a product string that says so — this is the one place
	// getting it backwards would be worse than not asking at all.
	if strings.Contains(lower, "samba") {
		return OSLinux, "Samba (Linux)", Medium,
			fmt.Sprintf("nmap: port %d is Samba, not Windows, serving the same ports", svc.Port)
	}

	switch {
	case strings.Contains(lower, "microsoft terminal services"), strings.Contains(lower, "ms-wbt-server"):
		return OSWindows, windowsVersionFrom(lower), High,
			fmt.Sprintf("nmap: port %d identifies as Microsoft Terminal Services", svc.Port)
	case strings.Contains(lower, "microsoft windows rpc"), strings.Contains(lower, "microsoft-ds"):
		return OSWindows, windowsVersionFrom(lower), Medium,
			fmt.Sprintf("nmap: port %d identifies as a Windows service", svc.Port)
	case strings.Contains(lower, "microsoft") || strings.Contains(lower, "windows"):
		return OSWindows, windowsVersionFrom(lower), Medium,
			fmt.Sprintf("nmap: port %d names Microsoft in its version string", svc.Port)
	}

	return OSUnknown, "", Low, ""
}

// windowsVersionFrom pulls a specific edition out of a version string when
// nmap's database happens to name one, e.g. "Windows 10", "Windows Server
// 2019" — falling back to the bare word when it only got that far.
func windowsVersionFrom(lower string) string {
	markers := []string{
		"windows server 2022", "windows server 2019", "windows server 2016",
		"windows server 2012", "windows server 2008",
		"windows 11", "windows 10", "windows 8", "windows 7", "windows vista", "windows xp",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return titleCase(m)
		}
	}
	if strings.Contains(lower, "windows") {
		return "Windows"
	}
	return ""
}

func titleCase(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "an open port"
}

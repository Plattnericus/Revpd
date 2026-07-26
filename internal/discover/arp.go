package discover

import (
	"os"
	"strings"
)

/*
	Finding a machine's hardware address.

	This is the part that matters most. A discovered machine is only useful if
	it can be woken, and Wake-on-LAN needs the MAC — an IP address alone gives
	somewhere to connect to once, and nothing at all after the machine sleeps.

	It comes out of the kernel's ARP table rather than off the wire. Asking for
	it directly would mean sending an ARP request, which needs a packet socket,
	which needs CAP_NET_RAW — a capability this service deliberately does not
	have. Connecting to the machine populates the table as a side effect, so by
	the time a probe has finished the answer is already there to read.
*/

// arpPaths is where the table lives. /proc/self/net is the same file, reached
// through the process's own directory: the unit runs with ProcSubset=pid,
// which hides everything in /proc that is not a process — /proc/net included.
var arpPaths = []string{"/proc/self/net/arp", "/proc/net/arp"}

// arpTable maps IP address to hardware address.
func arpTable() map[string]string {
	for _, path := range arpPaths {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		return parseARP(string(body))
	}
	return map[string]string{}
}

// parseARP reads the kernel's table.
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.40     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
//
// Incomplete entries carry an all-zero address and flags without 0x2. They
// mean "asked, no answer yet" and are worse than nothing here: a target saved
// with 00:00:00:00:00:00 would fail to wake with no clue why.
func parseARP(body string) map[string]string {
	out := map[string]string{}

	for i, line := range strings.Split(body, "\n") {
		if i == 0 {
			continue // the header
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		ip, flags, mac := fields[0], fields[2], strings.ToLower(fields[3])

		// Flag 0x2 is ATF_COM: the entry is complete.
		if !hasCompleteFlag(flags) {
			continue
		}
		if mac == "" || mac == "00:00:00:00:00:00" || !looksLikeMAC(mac) {
			continue
		}
		out[ip] = mac
	}
	return out
}

// hasCompleteFlag checks the ATF_COM bit in the hex flags column.
func hasCompleteFlag(flags string) bool {
	v := strings.TrimPrefix(strings.ToLower(flags), "0x")
	n := 0
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			n = n*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			n = n*16 + int(c-'a') + 10
		default:
			return false
		}
	}
	return n&0x2 != 0
}

func looksLikeMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, c := range p {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				return false
			}
		}
	}
	return true
}

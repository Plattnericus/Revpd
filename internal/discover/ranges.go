package discover

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// MaxHosts caps how large a range may be.
//
// A /22 is a thousand addresses and takes a few seconds. A /8 is sixteen
// million and would look exactly like a port scan of somebody else's network,
// which is not a thing this should be capable of doing by accident.
const MaxHosts = 1024

// LocalRange is a network this machine is attached to, offered as somewhere
// worth looking.
type LocalRange struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	Address   string `json:"address"`
	Hosts     int    `json:"hosts"`

	// TooLarge is set when the prefix covers more than MaxHosts. The range is
	// still shown — knowing it exists is useful — but it cannot be swept whole.
	TooLarge bool `json:"too_large"`
}

// LocalRanges lists the IPv4 networks this machine sits on.
//
// Only IPv4: Wake-on-LAN is an IPv4 broadcast mechanism, and a /64 of IPv6 is
// not something anyone sweeps.
func LocalRanges() ([]LocalRange, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not list the network interfaces: %w", err)
	}

	var out []LocalRange
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}

			prefix, err := netip.ParsePrefix(ipnet.String())
			if err != nil {
				continue
			}
			prefix = prefix.Masked()

			// A gateway is normally on the same private network as the
			// machines it wakes. Anything else is somebody else's business.
			if !isPrivate(prefix.Addr()) {
				continue
			}

			hosts := hostCount(prefix.Bits())
			out = append(out, LocalRange{
				Interface: iface.Name,
				CIDR:      prefix.String(),
				Address:   ipnet.IP.String(),
				Hosts:     hosts,
				TooLarge:  hosts > MaxHosts,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out, nil
}

// Expand lists the addresses a sweep would visit.
//
// The network and broadcast addresses are left out: neither is a machine, and
// probing a broadcast address is a good way to annoy an entire subnet.
func Expand(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("%q is not a network like 192.168.1.0/24", cidr)
	}
	prefix = prefix.Masked()

	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("%s is not an IPv4 network", cidr)
	}
	if !isPrivate(prefix.Addr()) {
		return nil, fmt.Errorf(
			"%s is not a private network. Scanning addresses that are not yours is not something this will do; "+
				"use one of 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 169.254.0.0/16", cidr)
	}

	if n := hostCount(prefix.Bits()); n > MaxHosts {
		return nil, fmt.Errorf(
			"%s covers %d addresses, which is more than the %d this will sweep at once. Narrow it — a /24 is the usual size",
			cidr, n, MaxHosts)
	}

	var out []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		// /31 and /32 have no network or broadcast address to skip: every
		// address in them is a host.
		if prefix.Bits() < 31 {
			if addr == prefix.Addr() {
				continue // the network address
			}
			if !prefix.Contains(addr.Next()) {
				continue // the broadcast address
			}
		}
		out = append(out, addr)
	}
	return out, nil
}

// hostCount is how many addresses a prefix covers, usable ones included.
func hostCount(bits int) int {
	if bits >= 31 {
		return 1 << (32 - bits)
	}
	// Minus the network and broadcast addresses.
	return (1 << (32 - bits)) - 2
}

// isPrivate reports whether an address belongs to a range a home or office
// network is built from.
func isPrivate(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

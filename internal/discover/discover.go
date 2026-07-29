// Package discover finds machines on the local network and works out what
// they are, so a target can be added by picking it from a list rather than by
// hunting for an IP address and a MAC by hand.
//
// Everything here works over ordinary TCP connections. That is not a
// simplification — it is what the service is allowed to do. The unit file
// grants CAP_NET_BIND_SERVICE and nothing else, and restricts sockets to
// AF_INET, AF_INET6 and AF_UNIX. Raw packets, which a ping sweep, an ARP
// request and nmap's OS detection all need, are out of reach by design.
//
// Connecting to a machine turns out to give almost everything worth having:
// the kernel fills in its hardware address as a side effect, an SSH greeting
// names the distribution, and an RDP negotiation identifies Windows.
package discover

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// DefaultPorts are probed on every address.
//
// Chosen for what they tell us rather than for coverage: 3389 is the reason
// any of this exists, 22 names the distribution, 445 and 139 mark a Windows
// machine, and 5985 marks one that is managed remotely.
var DefaultPorts = []int{3389, 22, 445, 139, 5985, 80, 443}

// probeKind is what to ask a port once it answers.
type probeKind int

const (
	probeNone probeKind = iota // it is open; that is all we wanted to know
	probeSSH                   // read the greeting, which names the distribution
	probeRDP                   // negotiate, which identifies Remote Desktop
)

// DefaultRoles maps a port to the question worth asking on it.
//
// Data rather than a switch on the port number: the pairing is a fact about
// the protocol, and keeping it here means a probe can be exercised on any port
// instead of only on the one it normally lives at.
var DefaultRoles = map[int]probeKind{
	22:   probeSSH,
	3389: probeRDP,
}

// Host is one machine that answered.
type Host struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	OpenPorts []int `json:"open_ports"`

	OS         OS         `json:"os"`
	Distro     string     `json:"distro,omitempty"`
	Confidence Confidence `json:"confidence"`
	Why        []string   `json:"why"`

	// Suggested is true when this looks like something worth adding: it speaks
	// RDP, or has the port open.
	Suggested bool `json:"suggested"`

	// Wakeable reports whether a hardware address was found. Without one the
	// machine can be reached while it is awake and never woken, which is worth
	// saying before somebody saves it and wonders why nothing happens.
	Wakeable bool `json:"wakeable"`
}

// Scanner probes addresses.
type Scanner struct {
	// Ports to try. Empty means DefaultPorts.
	Ports []int

	// Timeout for one connection. Short: on a local network anything alive
	// answers in milliseconds, and the whole sweep waits on the slowest probe.
	Timeout time.Duration

	// Concurrency caps how many connections are open at once. The unit allows
	// 8192 file descriptors; this stays well inside that while still finishing
	// a /24 in a couple of seconds.
	Concurrency int

	// Roles decides what to ask each port. Empty means DefaultRoles.
	Roles map[int]probeKind

	// dial exists so the tests can stand in for the network.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s Scanner) withDefaults() Scanner {
	if len(s.Ports) == 0 {
		s.Ports = DefaultPorts
	}
	if s.Roles == nil {
		s.Roles = DefaultRoles
	}
	if s.Timeout <= 0 {
		s.Timeout = 700 * time.Millisecond
	}
	if s.Concurrency <= 0 {
		s.Concurrency = 256
	}
	if s.dial == nil {
		d := &net.Dialer{}
		s.dial = d.DialContext
	}
	return s
}

// Sweep probes every address in a network and returns the ones that answered.
func (s Scanner) Sweep(ctx context.Context, cidr string) ([]Host, error) {
	addrs, err := Expand(cidr)
	if err != nil {
		return nil, err
	}

	s = s.withDefaults()

	// Read the hardware addresses once at the end rather than per host: the
	// table is only filled in by the connections this sweep makes.
	var (
		mu    sync.Mutex
		found []Host
		wg    sync.WaitGroup
		sem   = make(chan struct{}, s.Concurrency)
	)

	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			h := s.probe(ctx, a.String())
			if h == nil {
				return
			}
			mu.Lock()
			found = append(found, *h)
			mu.Unlock()
		}(addr)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.attachHardware(found)
	s.attachNames(ctx, found)

	// Enriches what is already found; never widens the scan. Nmap only runs
	// against addresses that already answered something, on ports already
	// known to be open, and only if it happens to be installed.
	s.enrichWithNmap(ctx, found)

	sort.Slice(found, func(i, j int) bool { return lessIP(found[i].IP, found[j].IP) })
	return found, nil
}

// attachNames resolves the found addresses in parallel. A network with no
// reverse records is normal, so this never holds anything up for long.
func (s Scanner) attachNames(ctx context.Context, hosts []Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			h.Hostname = reverseDNS(ctx, h.IP)
		}(&hosts[i])
	}
	wg.Wait()
}

// Probe examines a single address, whether or not it answers on any port.
//
// Unlike a sweep this always returns a result: somebody who typed an address
// deserves to be told it is not answering, rather than getting an empty list.
func (s Scanner) Probe(ctx context.Context, ip string) (*Host, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("%q is not an IP address", ip)
	}
	if !addr.Is4() {
		return nil, errors.New("only IPv4 addresses can be woken over the network")
	}

	s = s.withDefaults()

	h := s.probe(ctx, addr.String())
	if h == nil {
		// Nothing answered. Still report the address, with what little is
		// known — the hardware address may be in the table from earlier.
		h = &Host{IP: addr.String(), OS: OSUnknown, Confidence: Low, OpenPorts: []int{}}
		h.Why = []string{"nothing answered on " + joinPorts(s.Ports) + " — the machine may be asleep or firewalled"}
	}

	// A one-element slice so the same code fills in the hardware address and
	// the same explanation appears when there is not one.
	one := []Host{*h}
	s.attachHardware(one)
	one[0].Hostname = reverseDNS(ctx, one[0].IP)
	s.enrichWithNmap(ctx, one)

	return &one[0], nil
}

// probe tries every port on one address and returns nil when none answered.
func (s Scanner) probe(ctx context.Context, ip string) *Host {
	var (
		mu   sync.Mutex
		open []int
		sigs Signals
		wg   sync.WaitGroup
	)

	for _, port := range s.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			conn := s.connect(ctx, ip, p)
			if conn == nil {
				return
			}
			defer conn.Close()

			mu.Lock()
			open = append(open, p)
			mu.Unlock()

			// Ask the ports that answer something useful.
			switch s.Roles[p] {
			case probeSSH:
				if b := readSSHBanner(conn); b != "" {
					mu.Lock()
					sigs.SSHBanner = b
					mu.Unlock()
				}
			case probeRDP:
				if rdpNegotiate(conn) {
					mu.Lock()
					sigs.RDPAccepted = true
					mu.Unlock()
				}
			}
		}(port)
	}
	wg.Wait()

	if len(open) == 0 {
		return nil
	}
	sort.Ints(open)
	sigs.OpenPorts = open

	g := Identify(sigs)
	return &Host{
		IP:         ip,
		OpenPorts:  open,
		OS:         g.OS,
		Distro:     g.Distro,
		Confidence: g.Confidence,
		Why:        g.Why,
		Suggested:  g.CanRDP(sigs),
	}
}

func (s Scanner) connect(ctx context.Context, ip string, port int) net.Conn {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	conn, err := s.dial(ctx, "tcp", net.JoinHostPort(ip, itoa(port)))
	if err != nil {
		return nil
	}
	return conn
}

// attachHardware fills in the MAC addresses the connections just caused the
// kernel to learn, and resolves names.
func (s Scanner) attachHardware(hosts []Host) {
	table := arpTable()

	for i := range hosts {
		if mac, ok := table[hosts[i].IP]; ok {
			hosts[i].MAC = mac
			hosts[i].Wakeable = true
		} else {
			hosts[i].Why = append(hosts[i].Why,
				"no hardware address — it cannot be woken from here, only reached while it is already on")
		}
	}
}

/* --------------------------------------------------------------- probes --- */

// readSSHBanner reads the greeting an SSH server sends before anything else.
//
// The protocol requires the server to speak first, so this costs one read and
// no handshake at all: the connection is closed before any key exchange.
func readSSHBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	line = trimCRLF(line)

	// Only a real greeting counts. Anything else on port 22 is something else.
	if len(line) < 4 || line[:4] != "SSH-" {
		return ""
	}
	return trim(line, 200)
}

// rdpNegotiate sends an X.224 connection request and reports whether the
// answer looks like a Remote Desktop server.
//
// This is the first exchange of the RDP handshake and nothing more: no
// credentials are offered and no session is started. A server that answers it
// is running Remote Desktop; almost nothing else on 3389 will.
func rdpNegotiate(conn net.Conn) bool {
	// TPKT header, then an X.224 connection request carrying the standard RDP
	// negotiation request asking for TLS.
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 19
		0x0e,                   // X.224 length
		0xe0,                   // connection request
		0x00, 0x00, 0x00, 0x00, // destination and source reference
		0x00,                   // class
		0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ, flags, length 8
		0x03, 0x00, 0x00, 0x00, // TLS + CredSSP
	}

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 19)
	n, err := readAtLeast(conn, resp, 6)
	if err != nil || n < 6 {
		return false
	}

	// TPKT version 3, then an X.224 connection confirm.
	return resp[0] == 0x03 && resp[5] == 0xd0
}

func readAtLeast(conn net.Conn, buf []byte, min int) (int, error) {
	total := 0
	for total < min {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

// reverseDNS asks for a name, briefly. A network without reverse records is
// normal and not worth waiting on.
func reverseDNS(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return trimTrailingDot(names[0])
}

/* ---------------------------------------------------------------- utils --- */

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// lessIP orders addresses the way people read them, so .2 comes before .10.
func lessIP(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return x.Less(y)
}

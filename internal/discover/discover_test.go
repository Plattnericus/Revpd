package discover

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

/*
	The probes are tested against real listeners rather than mocks: an SSH
	greeting and an RDP negotiation are wire formats, and a stub that agrees
	with my reading of them would prove nothing.
*/

// fakeServer answers on a port the way some real thing would.
func fakeServer(t *testing.T, answer func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if answer != nil {
					answer(conn)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func port(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

/* -------------------------------------------------------------- probes --- */

func TestSSHBannerIsRead(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := readSSHBanner(conn)
	if !strings.Contains(got, "Debian") {
		t.Fatalf("banner = %q", got)
	}
	// The trailing CRLF has no business being shown to anyone.
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("banner still carries line endings: %q", got)
	}
}

// Something else listening on 22 must not be mistaken for SSH.
func TestSSHBannerRejectsSomethingElse(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	if got := readSSHBanner(conn); got != "" {
		t.Fatalf("an HTTP server was read as an SSH banner: %q", got)
	}
}

func TestSSHBannerOnSilentPort(t *testing.T) {
	// Accepts the connection and says nothing, which is what a port forwarded
	// to something asleep looks like.
	addr := fakeServer(t, func(c net.Conn) { time.Sleep(200 * time.Millisecond) })

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	if got := readSSHBanner(conn); got != "" {
		t.Fatalf("silence was read as a banner: %q", got)
	}
}

func TestRDPNegotiationIsRecognised(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		// Read the request, then answer with a connection confirm the way a
		// Remote Desktop server does.
		buf := make([]byte, 64)
		c.Read(buf)
		c.Write([]byte{
			0x03, 0x00, 0x00, 0x13, // TPKT
			0x0e, 0xd0, // X.224 connection confirm
			0x00, 0x00, 0x12, 0x34, 0x00,
			0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
		})
		time.Sleep(50 * time.Millisecond)
	})

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	if !rdpNegotiate(conn) {
		t.Fatal("a Remote Desktop server was not recognised")
	}
}

// A web server on 3389 answers, but not like this.
func TestRDPNegotiationRejectsSomethingElse(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		c.Read(buf)
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	if rdpNegotiate(conn) {
		t.Fatal("a web server was mistaken for Remote Desktop")
	}
}

func TestRDPNegotiationOnSilentPort(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) { time.Sleep(200 * time.Millisecond) })

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	if rdpNegotiate(conn) {
		t.Fatal("silence was read as a negotiation")
	}
}

/* --------------------------------------------------------------- probe --- */

// A whole probe against a machine pretending to be a Debian box with xrdp.
func TestProbeIdentifiesADebianMachine(t *testing.T) {
	ssh := fakeServer(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"))
		time.Sleep(100 * time.Millisecond)
	})

	p := port(t, ssh)
	s := Scanner{
		Ports:   []int{p},
		Roles:   map[int]probeKind{p: probeSSH},
		Timeout: time.Second,
	}
	h := s.withDefaults().probe(context.Background(), "127.0.0.1")

	if h == nil {
		t.Fatal("the machine did not answer at all")
	}
	if h.OS != OSLinux {
		t.Errorf("os = %q, want linux", h.OS)
	}
	if h.Distro != "Debian" {
		t.Errorf("distro = %q, want Debian", h.Distro)
	}
	if h.Confidence != High {
		t.Errorf("confidence = %q, want high", h.Confidence)
	}
}

func TestProbeReturnsNothingForASilentAddress(t *testing.T) {
	// Port 1 on loopback: nothing is listening, and the connection is refused
	// immediately rather than timing out.
	s := Scanner{Ports: []int{1}, Timeout: 300 * time.Millisecond}
	if h := s.withDefaults().probe(context.Background(), "127.0.0.1"); h != nil {
		t.Fatalf("an address with nothing on it was reported as a machine: %+v", h)
	}
}

// Somebody who types an address deserves an answer either way.
func TestProbeAlwaysAnswersForATypedAddress(t *testing.T) {
	s := Scanner{Ports: []int{1}, Timeout: 300 * time.Millisecond}

	h, err := s.Probe(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if h.IP != "127.0.0.1" {
		t.Errorf("ip = %q", h.IP)
	}
	if len(h.Why) == 0 {
		t.Error("no explanation for a machine that said nothing")
	}
	if !strings.Contains(strings.Join(h.Why, " "), "asleep") {
		t.Errorf("the explanation does not suggest what to check: %v", h.Why)
	}
}

func TestProbeRejectsNonsense(t *testing.T) {
	s := Scanner{}
	for _, in := range []string{"", "hello", "999.1.1.1", "192.168.1.0/24"} {
		if _, err := s.Probe(context.Background(), in); err == nil {
			t.Errorf("accepted %q as an address", in)
		}
	}

	// IPv6 cannot be woken over the network, so it is refused with a reason
	// rather than probed and then found useless.
	_, err := s.Probe(context.Background(), "::1")
	if err == nil {
		t.Fatal("accepted an IPv6 address")
	}
	if !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

/* --------------------------------------------------------------- sweep --- */

func TestSweepRefusesRangesThatAreNotYours(t *testing.T) {
	s := Scanner{}

	// A public range. Sweeping it would be scanning somebody else's network.
	_, err := s.Sweep(context.Background(), "8.8.8.0/24")
	if err == nil {
		t.Fatal("swept a public range")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

func TestSweepRefusesRangesThatAreTooBig(t *testing.T) {
	_, err := Scanner{}.Sweep(context.Background(), "10.0.0.0/8")
	if err == nil {
		t.Fatal("accepted a /8")
	}
	for _, want := range []string{"16777214", "/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

func TestSweepStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 192.168.0.0/24 is private and small, so only the cancellation stops it.
	if _, err := (Scanner{}).Sweep(ctx, "192.168.0.0/24"); err == nil {
		t.Fatal("a cancelled sweep ran to completion")
	}
}

/* -------------------------------------------------------------- ranges --- */

func TestExpandSkipsNetworkAndBroadcast(t *testing.T) {
	addrs, err := Expand("192.168.1.0/29")
	if err != nil {
		t.Fatal(err)
	}

	got := make([]string, len(addrs))
	for i, a := range addrs {
		got[i] = a.String()
	}
	want := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// A /32 is one machine and a /31 is a point-to-point link. Neither has a
// network or broadcast address to leave out.
func TestExpandHandlesTinyPrefixes(t *testing.T) {
	one, err := Expand("192.168.1.5/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].String() != "192.168.1.5" {
		t.Fatalf("/32 expanded to %v", one)
	}

	two, err := Expand("192.168.1.4/31")
	if err != nil {
		t.Fatal(err)
	}
	if len(two) != 2 {
		t.Fatalf("/31 expanded to %v", two)
	}
}

func TestExpandAcceptsEveryPrivateRange(t *testing.T) {
	for _, cidr := range []string{
		"10.1.2.0/24",
		"172.16.5.0/24",
		"192.168.1.0/24",
		"169.254.10.0/24", // link-local, which is what a machine without DHCP picks
	} {
		if _, err := Expand(cidr); err != nil {
			t.Errorf("%s was refused: %v", cidr, err)
		}
	}
}

func TestExpandRejectsMalformed(t *testing.T) {
	for _, in := range []string{"", "192.168.1.1", "hello/24", "192.168.1.0/33"} {
		if _, err := Expand(in); err == nil {
			t.Errorf("accepted %q as a network", in)
		}
	}
}

func TestHostCount(t *testing.T) {
	cases := map[int]int{24: 254, 25: 126, 30: 2, 31: 2, 32: 1, 22: 1022}
	for bits, want := range cases {
		if got := hostCount(bits); got != want {
			t.Errorf("hostCount(/%d) = %d, want %d", bits, got, want)
		}
	}
}

// The local ranges are what the interface offers as somewhere to look. They
// have to be real networks this machine is on, and small enough to sweep.
func TestLocalRangesAreUsable(t *testing.T) {
	ranges, err := LocalRanges()
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range ranges {
		if _, err := Expand(r.CIDR); err != nil && !r.TooLarge {
			t.Errorf("%s is offered but cannot be swept: %v", r.CIDR, err)
		}
		if r.Interface == "" {
			t.Errorf("%s has no interface name", r.CIDR)
		}
		if (r.Hosts > MaxHosts) != r.TooLarge {
			t.Errorf("%s: hosts=%d but too_large=%v", r.CIDR, r.Hosts, r.TooLarge)
		}
	}
}

package discover

import (
	"strings"
	"testing"
)

/*
	The banners are real ones, copied from the machines they came from. A
	fingerprinter tested against strings invented to match it proves only that
	it matches its own invention.
*/

func TestIdentifiesFromRealSSHBanners(t *testing.T) {
	cases := []struct {
		banner string
		os     OS
		distro string
		conf   Confidence
	}{
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", OSLinux, "Debian", High},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", OSLinux, "Ubuntu", High},
		{"SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3", OSLinux, "Raspberry Pi OS", High},
		{"SSH-2.0-OpenSSH_9.3 FreeBSD-20230719", OSLinux, "FreeBSD", High},

		// Windows ships OpenSSH now and says so.
		{"SSH-2.0-OpenSSH_for_Windows_9.5", OSWindows, "Windows", High},

		// A distribution that does not name itself is still clearly not Windows.
		{"SSH-2.0-OpenSSH_9.6", OSLinux, "", Medium},
		{"SSH-2.0-dropbear_2022.83", OSLinux, "", Medium},
	}

	for _, c := range cases {
		g := Identify(Signals{OpenPorts: []int{22}, SSHBanner: c.banner})

		if g.OS != c.os {
			t.Errorf("%q: os = %q, want %q", c.banner, g.OS, c.os)
		}
		if g.Distro != c.distro {
			t.Errorf("%q: distro = %q, want %q", c.banner, g.Distro, c.distro)
		}
		if g.Confidence != c.conf {
			t.Errorf("%q: confidence = %q, want %q", c.banner, g.Confidence, c.conf)
		}
		if len(g.Why) == 0 {
			t.Errorf("%q: reached a conclusion with no reason given", c.banner)
		}
	}
}

func TestRDPMakesItWindows(t *testing.T) {
	g := Identify(Signals{OpenPorts: []int{3389}, RDPAccepted: true})

	if g.OS != OSWindows || g.Confidence != High {
		t.Fatalf("os = %q, confidence = %q", g.OS, g.Confidence)
	}
	if !strings.Contains(strings.Join(g.Why, " "), "3389") {
		t.Errorf("the reason does not mention the negotiation: %v", g.Why)
	}
}

// A Linux box running xrdp answers both. Calling it Windows would send someone
// looking for a Windows machine that does not exist, so the disagreement is
// reported rather than resolved in favour of whichever ran last.
func TestLinuxWithXrdpIsNotCalledWindows(t *testing.T) {
	g := Identify(Signals{
		OpenPorts:   []int{22, 3389},
		SSHBanner:   "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
		RDPAccepted: true,
	})

	if g.OS != OSLinux {
		t.Fatalf("os = %q, want linux — SSH named the distribution outright", g.OS)
	}
	if g.Distro != "Debian" {
		t.Errorf("distro = %q", g.Distro)
	}
	if !strings.Contains(strings.Join(g.Why, " "), "xrdp") {
		t.Errorf("the disagreement is not explained: %v", g.Why)
	}
}

// Windows with SSH turned off, which is the usual state of a desktop.
func TestWindowsWithoutSSH(t *testing.T) {
	cases := []struct {
		name  string
		ports []int
		conf  Confidence
	}{
		{"remote management", []int{5985}, High},
		{"file sharing", []int{445, 139}, Medium},
		{"just the desktop port", []int{3389}, Medium},
	}

	for _, c := range cases {
		g := Identify(Signals{OpenPorts: c.ports})
		if g.OS != OSWindows {
			t.Errorf("%s: os = %q, want windows", c.name, g.OS)
		}
		if g.Confidence != c.conf {
			t.Errorf("%s: confidence = %q, want %q", c.name, g.Confidence, c.conf)
		}
	}
}

// A machine that answers but gives nothing away is still worth listing, and
// must not be labelled with a guess that was never made.
func TestSilentMachineIsNotGuessedAt(t *testing.T) {
	g := Identify(Signals{OpenPorts: []int{80, 443}})

	if g.OS != OSUnknown {
		t.Errorf("os = %q, want unknown", g.OS)
	}
	if g.Confidence != Low {
		t.Errorf("confidence = %q, want low", g.Confidence)
	}
	if len(g.Why) == 0 {
		t.Fatal("no explanation at all")
	}
	if !strings.Contains(strings.Join(g.Why, " "), "did not identify itself") {
		t.Errorf("the reason is not honest about the uncertainty: %v", g.Why)
	}
}

func TestNothingOpenSaysNothing(t *testing.T) {
	g := Identify(Signals{})
	if g.OS != OSUnknown || len(g.Why) != 0 {
		t.Fatalf("invented a conclusion from no evidence: %+v", g)
	}
}

// Whether to offer a machine as a target is a separate question from what it
// is: a Linux box with xrdp is worth adding, and a Windows box with the port
// shut is not reachable.
func TestSuggestsWhatCanActuallyBeReached(t *testing.T) {
	rdp := Signals{OpenPorts: []int{3389}, RDPAccepted: true}
	if !Identify(rdp).CanRDP(rdp) {
		t.Error("a Remote Desktop server was not suggested")
	}

	xrdp := Signals{OpenPorts: []int{22, 3389}, SSHBanner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", RDPAccepted: true}
	if !Identify(xrdp).CanRDP(xrdp) {
		t.Error("a Linux box running xrdp was not suggested")
	}

	web := Signals{OpenPorts: []int{80, 443}}
	if Identify(web).CanRDP(web) {
		t.Error("a machine with no Remote Desktop port was suggested anyway")
	}
}

/* ----------------------------------------------------------------- arp --- */

func TestParseARPReadsTheKernelTable(t *testing.T) {
	// Straight from /proc/net/arp on a Debian box.
	table := parseARP(`IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         3c:37:86:11:22:33     *        eth0
192.168.1.40     0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`)

	if got := table["192.168.1.1"]; got != "3c:37:86:11:22:33" {
		t.Errorf("router mac = %q", got)
	}

	// Case is normalised: a MAC saved in one case and compared in another
	// would silently fail to match.
	if got := table["192.168.1.40"]; got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q, want it lower-cased", got)
	}

	// Flags without 0x2 mean "asked, no answer". Saving that address would
	// produce a target that fails to wake with no clue why.
	if _, ok := table["192.168.1.99"]; ok {
		t.Error("an incomplete entry was returned as a usable address")
	}
}

func TestParseARPIgnoresRubbish(t *testing.T) {
	table := parseARP(`IP address       HW type     Flags       HW address            Mask     Device
short line
192.168.1.5      0x1         0x2         not-a-mac             *        eth0
192.168.1.6      0x1         zz          aa:bb:cc:dd:ee:ff     *        eth0
`)

	if len(table) != 0 {
		t.Errorf("accepted malformed entries: %v", table)
	}
}

func TestParseARPOnAnEmptyTable(t *testing.T) {
	if got := parseARP(""); len(got) != 0 {
		t.Errorf("got %v from nothing", got)
	}
	if got := parseARP("IP address       HW type     Flags       HW address            Mask     Device\n"); len(got) != 0 {
		t.Errorf("got %v from a header alone", got)
	}
}

func TestLooksLikeMAC(t *testing.T) {
	good := []string{"aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"}
	bad := []string{"", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff", "aabbccddeeff", "a:b:c:d:e:f"}

	for _, s := range good {
		if !looksLikeMAC(s) {
			t.Errorf("%q was rejected", s)
		}
	}
	for _, s := range bad {
		if looksLikeMAC(s) {
			t.Errorf("%q was accepted", s)
		}
	}
}

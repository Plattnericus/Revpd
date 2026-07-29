package discover

import (
	"strings"
	"testing"
)

/*
	The XML fixtures below are shaped exactly like nmap's own -oX schema —
	the tags and attributes it actually emits, not a shorthand invented to
	match the parser. A parser tested against its own invented shape proves
	only that it agrees with itself.
*/

func TestParseNmapXMLReadsWhatVersionDetectionFound(t *testing.T) {
	const report = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.40" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" ostype="Windows" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Microsoft Windows 10 microsoft-ds" ostype="Windows" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.41" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	got, err := parseNmapXML([]byte(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	windows, ok := got["192.168.1.40"]
	if !ok {
		t.Fatal("no result for 192.168.1.40")
	}
	if len(windows.services) != 2 {
		t.Fatalf("192.168.1.40: got %d services, want 2 (the closed port must be excluded)", len(windows.services))
	}
	if windows.services[0].OSType != "Windows" {
		t.Errorf("service ostype = %q, want Windows", windows.services[0].OSType)
	}
	if windows.services[0].Product != "Microsoft Terminal Services" {
		t.Errorf("product = %q", windows.services[0].Product)
	}

	linux, ok := got["192.168.1.41"]
	if !ok {
		t.Fatal("no result for 192.168.1.41")
	}
	if len(linux.services) != 1 || linux.services[0].Version != "9.2p1" {
		t.Fatalf("192.168.1.41: got %+v", linux.services)
	}
}

func TestParseNmapXMLSkipsPortsWithNoUsefulEvidence(t *testing.T) {
	const report = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="open"/>
        <service method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	got, err := parseNmapXML([]byte(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// A service element with no name, product or ostype is nmap admitting it
	// does not know — that must not become a phantom host in the result.
	if _, ok := got["10.0.0.5"]; ok {
		t.Error("a host with no identifiable service produced a result anyway")
	}
}

func TestParseNmapXMLRejectsGarbage(t *testing.T) {
	if _, err := parseNmapXML([]byte("not xml at all")); err == nil {
		t.Fatal("garbage input was accepted")
	}
}

/* -------------------------------------------------------------- fusion --- */

func TestNmapGuessRecognisesWindowsServices(t *testing.T) {
	cases := []struct {
		name     string
		svc      nmapService
		wantOS   OS
		wantConf Confidence
	}{
		{
			"ostype field says Windows outright",
			nmapService{Port: 445, Product: "Samba smbd 3.X", OSType: "Windows"},
			OSWindows, High,
		},
		{
			"Terminal Services by name, no ostype",
			nmapService{Port: 3389, Product: "Microsoft Terminal Services"},
			OSWindows, High,
		},
		{
			"a Microsoft product string with no ostype",
			nmapService{Port: 135, Product: "Microsoft Windows RPC"},
			OSWindows, Medium,
		},
		{
			"ostype says Linux",
			nmapService{Port: 22, Product: "OpenSSH", OSType: "Linux"},
			OSLinux, Medium,
		},
		{
			"nothing recognisable",
			nmapService{Port: 8080, Product: "nginx", Version: "1.24"},
			OSUnknown, Low,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os, _, conf, reason := nmapGuess(tc.svc)
			if os != tc.wantOS {
				t.Errorf("os = %q, want %q", os, tc.wantOS)
			}
			if os != OSUnknown && conf != tc.wantConf {
				t.Errorf("confidence = %q, want %q", conf, tc.wantConf)
			}
			if os != OSUnknown && reason == "" {
				t.Error("reached a conclusion with no reason given")
			}
		})
	}
}

// Samba serves the same ports a real Windows file share does. Getting this
// backwards would be worse than not asking nmap at all — a Linux box would be
// pitched to the user as a Windows target it can never actually forward RDP
// to.
func TestNmapGuessDoesNotMistakeSambaForWindows(t *testing.T) {
	os, distro, _, reason := nmapGuess(nmapService{
		Port: 445, Product: "Samba smbd 4.17.12-Debian",
	})
	if os != OSLinux {
		t.Fatalf("os = %q, want linux — Samba is not Windows", os)
	}
	if !strings.Contains(strings.ToLower(distro+reason), "samba") {
		t.Errorf("neither distro nor reason mentions Samba: distro=%q reason=%q", distro, reason)
	}
}

func TestNmapGuessNamesTheWindowsEdition(t *testing.T) {
	_, distro, _, _ := nmapGuess(nmapService{
		Port: 445, Product: "Microsoft Windows Server 2019 microsoft-ds",
	})
	if distro != "Windows Server 2019" {
		t.Errorf("distro = %q, want a specific edition", distro)
	}
}

func TestRefineWithNmapUpgradesAnUnknownGuess(t *testing.T) {
	h := &Host{OS: OSUnknown, Confidence: Low, OpenPorts: []int{445}}
	refineWithNmap(h, []nmapService{{Port: 445, Product: "Microsoft Windows 10 microsoft-ds", OSType: "Windows"}})

	if h.OS != OSWindows {
		t.Fatalf("os = %q, want windows", h.OS)
	}
	if h.Confidence != High {
		t.Errorf("confidence = %q, want high", h.Confidence)
	}
	if len(h.Why) == 0 {
		t.Error("no reason was recorded")
	}
}

// The whole point of ranking confidence: an RDP negotiation that actually
// completed is stronger evidence than a version-probe string, and nmap
// disagreeing with it must not overwrite a correct answer.
func TestRefineWithNmapNeverDowngradesAStrongerNativeGuess(t *testing.T) {
	h := &Host{OS: OSWindows, Confidence: High, Distro: "Windows", OpenPorts: []int{3389}}
	refineWithNmap(h, []nmapService{{Port: 3389, Product: "OpenSSH", OSType: "Linux"}})

	if h.OS != OSWindows {
		t.Fatalf("a weaker, contradicting nmap signal overwrote a high-confidence native guess: os = %q", h.OS)
	}
}

// A confident nmap match is allowed to firm up a merely-plausible native
// guess — this is the case that actually matters most in practice, since the
// native prober alone only gets to Medium confidence from open ports alone.
func TestRefineWithNmapUpgradesAWeakerNativeGuess(t *testing.T) {
	h := &Host{OS: OSWindows, Confidence: Medium, OpenPorts: []int{445, 139}}
	refineWithNmap(h, []nmapService{{Port: 445, Product: "Microsoft Windows Server 2022 microsoft-ds", OSType: "Windows"}})

	if h.Confidence != High {
		t.Errorf("confidence = %q, want high after a confident nmap match", h.Confidence)
	}
	if h.Distro != "Windows Server 2022" {
		t.Errorf("distro = %q, want the specific edition nmap found", h.Distro)
	}
}

func TestRunNmapRejectsEmptyInput(t *testing.T) {
	if _, err := runNmap(t.Context(), "nmap", nil, []int{80}); err == nil {
		t.Error("no targets was accepted")
	}
	if _, err := runNmap(t.Context(), "nmap", []string{"127.0.0.1"}, nil); err == nil {
		t.Error("no ports was accepted")
	}
}

// The one thing that must never be true regardless of what is installed:
// enrichment can only be skipped, never make a sweep fail.
func TestEnrichWithNmapIsANoOpWithoutHostsOrPorts(t *testing.T) {
	s := Scanner{}
	// Must not panic, and must not block, whether or not nmap happens to be
	// on this machine's PATH.
	s.enrichWithNmap(t.Context(), nil)
	s.enrichWithNmap(t.Context(), []Host{{IP: "192.168.1.1"}}) // no open ports
}

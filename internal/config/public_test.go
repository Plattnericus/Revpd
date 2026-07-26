package config

import (
	"strings"
	"testing"
	"time"
)

func TestCheckPublicHost(t *testing.T) {
	good := []string{
		"",
		"gw.example.com",
		"gw",
		"my-gateway.dyndns.org",
		"203.0.113.9",
		"2001:4860:4860::8888",
		"xn--bcher-kva.example",
	}
	for _, h := range good {
		if err := CheckPublicHost(h); err != nil {
			t.Errorf("CheckPublicHost(%q) = %v, want accepted", h, err)
		}
	}

	// Each of these would produce a connect string Remote Desktop cannot be
	// given, so it is refused with the fix rather than printed.
	bad := map[string]string{
		"https://gw.example.com": "without https://",
		"gw.example.com:3389":    "public.rdp_port",
		"gw.example.com/portal":  "no path",
		"gw example.com":         "no path",
		"-gw.example.com":        "not a valid hostname",
		"gw-.example.com":        "not a valid hostname",
		"gw..example.com":        "not a valid hostname",
		"gw_1.example.com":       "not a valid hostname",
		"user@gw.example.com":    "no path",
	}
	for h, want := range bad {
		err := CheckPublicHost(h)
		if err == nil {
			t.Errorf("CheckPublicHost(%q) should have failed", h)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPublicHost(%q) = %v, should mention %q", h, err, want)
		}
	}
}

func TestPublicPortsFallBackToTheListener(t *testing.T) {
	c := Defaults()

	// Nothing configured: the router forwards the same number through, which
	// is both the default and what most people set up.
	if got := c.PublicRDPPort(); got != 3389 {
		t.Errorf("PublicRDPPort() = %d, want 3389", got)
	}
	if got := c.PublicPortalPort(); got != 443 {
		t.Errorf("PublicPortalPort() = %d, want 443", got)
	}

	// A high port forwarded to 3389 keeps the internet's constant scan of
	// 3389 off the door, and the printed address has to say so.
	c.Public.RDPPort = 33890
	c.Public.PortalPort = 8443
	if got := c.PublicRDPPort(); got != 33890 {
		t.Errorf("PublicRDPPort() = %d, want the forwarded port", got)
	}
	if got := c.PublicPortalPort(); got != 8443 {
		t.Errorf("PublicPortalPort() = %d, want the forwarded port", got)
	}

	// The local listener still speaks for itself.
	c = Defaults()
	c.Relay.Listen = ":13389"
	if got := c.PublicRDPPort(); got != 13389 {
		t.Errorf("PublicRDPPort() = %d, want the listener's port", got)
	}
}

func TestPublicHostFallsBackToHostname(t *testing.T) {
	c := Defaults()

	// The default hostname is a placeholder and would be wrong for everyone.
	if got := c.PublicHost(); got != "" {
		t.Errorf("PublicHost() = %q, want nothing for an unconfigured gateway", got)
	}

	// An installation that set a real hostname is already correct and should
	// not have to say the same thing twice.
	c.Web.Hostname = "gw.example.com"
	if got := c.PublicHost(); got != "gw.example.com" {
		t.Errorf("PublicHost() = %q, want the hostname", got)
	}

	c.Public.Host = "remote.example.org"
	if got := c.PublicHost(); got != "remote.example.org" {
		t.Errorf("PublicHost() = %q, want public.host to win", got)
	}
}

func TestValidateRejectsBadPublicSettings(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"a scheme in the host": {
			func(c *Config) { c.Public.Host = "https://gw.example.com" },
			"without https://",
		},
		"a resolver over plain HTTP": {
			// The answer decides the address the portal hands out. Over HTTP
			// anyone on the path gets to choose it.
			func(c *Config) { c.Public.Resolvers = []string{"http://api.example.com"} },
			"https://",
		},
		"detection with nobody to ask": {
			func(c *Config) { c.Public.Resolvers = nil },
			"nobody to ask",
		},
		"a refresh that hammers the resolvers": {
			func(c *Config) { c.Public.Refresh = time.Second },
			"public.refresh",
		},
		"a port out of range": {
			func(c *Config) { c.Public.RDPPort = 70000 },
			"public.rdp_port",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Web.Hostname = "gw.example.com"
			c.mutate(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("should have been rejected")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should mention %q: %v", c.want, err)
			}
		})
	}
}

func TestValidateAcceptsDetectionTurnedOff(t *testing.T) {
	// With detection off there is nobody to ask, and that is the point: the
	// gateway never mentions itself to a third party.
	cfg := Defaults()
	cfg.Web.Hostname = "gw.example.com"
	cfg.Public.Detect = false
	cfg.Public.Resolvers = nil
	cfg.Public.Refresh = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("switching detection off should be allowed: %v", err)
	}
}

func TestPublicSettingsApplyThroughTheRegistry(t *testing.T) {
	base := Defaults()
	base.Web.Hostname = "gw.example.com"

	got, unknown, err := Apply(base, map[string]string{
		"public.host":        " remote.example.org ",
		"public.rdp_port":    "33890",
		"public.detect":      "false",
		"public.portal_port": "",
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown keys: %v", unknown)
	}

	if got.Public.Host != "remote.example.org" {
		t.Errorf("host = %q, want it trimmed", got.Public.Host)
	}
	if got.Public.RDPPort != 33890 {
		t.Errorf("rdp_port = %d, want 33890", got.Public.RDPPort)
	}
	if got.Public.Detect {
		t.Error("detect should be off")
	}
	// An emptied port field means "same as the listener", not an error.
	if got.Public.PortalPort != 0 {
		t.Errorf("portal_port = %d, want 0", got.Public.PortalPort)
	}
}

func TestRegistryRejectsABadPublicHost(t *testing.T) {
	base := Defaults()
	base.Web.Hostname = "gw.example.com"

	if _, _, err := Apply(base, map[string]string{"public.host": "gw.example.com:3389"}); err == nil {
		t.Fatal("a host with a port should be refused")
	}

	// A refused save changes nothing at all.
	if base.Public.Host != "" {
		t.Errorf("the base config was modified: %q", base.Public.Host)
	}
}

func TestEveryPublicSettingIsEditable(t *testing.T) {
	// The point of the feature is that it can be set from the web interface,
	// so a field added to the struct without a registry entry is a bug.
	want := []string{
		"public.host", "public.detect", "public.rdp_port",
		"public.portal_port", "public.resolvers", "public.refresh",
	}
	for _, key := range want {
		s, ok := Lookup(key)
		if !ok {
			t.Errorf("%s is not editable from the settings page", key)
			continue
		}
		if s.Group != GroupPublic {
			t.Errorf("%s is in group %q, want %q", key, s.Group, GroupPublic)
		}
	}
}

func TestPublicAddressSettingsNeedNoRestart(t *testing.T) {
	// These describe what is already true on the far side of the router.
	// Nothing binds to them, so asking for a restart would drop every open
	// desktop session to change a printed address.
	for _, key := range []string{"public.host", "public.detect", "public.rdp_port", "public.portal_port"} {
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is missing", key)
		}
		if s.NeedsRestart() {
			t.Errorf("%s should take effect immediately", key)
		}
	}
}

func TestPublicEnvOverrides(t *testing.T) {
	t.Setenv("REVPD_PUBLIC_HOST", "env.example.com")
	t.Setenv("REVPD_PUBLIC_DETECT", "off")
	t.Setenv("REVPD_PUBLIC_RDP_PORT", "33890")
	t.Setenv("REVPD_PUBLIC_PORTAL_PORT", "8443")
	t.Setenv("REVPD_PUBLIC_REFRESH", "2h")
	t.Setenv("REVPD_PUBLIC_RESOLVERS", "https://one.example.com, https://two.example.com")

	c := Defaults()
	c.applyEnv()

	if c.Public.Host != "env.example.com" {
		t.Errorf("host = %q", c.Public.Host)
	}
	if c.Public.Detect {
		t.Error("detect should be off")
	}
	if c.Public.RDPPort != 33890 || c.Public.PortalPort != 8443 {
		t.Errorf("ports = %d/%d", c.Public.RDPPort, c.Public.PortalPort)
	}
	if c.Public.Refresh != 2*time.Hour {
		t.Errorf("refresh = %v", c.Public.Refresh)
	}
	if len(c.Public.Resolvers) != 2 || c.Public.Resolvers[0] != "https://one.example.com" {
		t.Errorf("resolvers = %v", c.Public.Resolvers)
	}
}

func TestEmptyResolversEnvClearsTheList(t *testing.T) {
	// A deployment that wants nothing asked has to be able to say so from the
	// environment alone, without a config file to edit.
	t.Setenv("REVPD_PUBLIC_RESOLVERS", "")

	c := Defaults()
	c.applyEnv()

	if len(c.Public.Resolvers) != 0 {
		t.Errorf("resolvers = %v, want none", c.Public.Resolvers)
	}
}

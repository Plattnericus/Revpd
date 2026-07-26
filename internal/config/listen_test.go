package config_test

import (
	"strings"
	"testing"

	"github.com/plattnericus/revpd/internal/config"
)

// What listens out of the box, and nothing beyond it.
//
// Two ports carry traffic — the RDP relay and the portal — on the numbers a
// client assumes so neither has to be typed. Port 80 is a third socket but not
// a third service: it answers every request with a redirect to the portal and
// serves nothing, so that someone who omits https:// still arrives.
func TestWhatListensByDefault(t *testing.T) {
	cfg := config.Defaults()

	if cfg.Relay.Listen != ":3389" {
		t.Fatalf("relay.listen = %q, want :3389", cfg.Relay.Listen)
	}
	if cfg.Web.Listen != ":443" {
		t.Fatalf("web.listen = %q, want :443", cfg.Web.Listen)
	}
	if cfg.Web.HTTPListen != ":80" {
		t.Fatalf("web.http_listen = %q, want :80", cfg.Web.HTTPListen)
	}

	// The remaining listener is opt-in and must stay off: it would be a real
	// fourth service, and it needs a certificate from a public CA to be any
	// use at all.
	if cfg.RDGW.Enabled {
		t.Fatal("the RD gateway listener is on by default")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}

// PortalIsPublic drives the self-signed-certificate warning, so it has to be
// right about what "reachable from outside" means.
func TestPortalIsPublic(t *testing.T) {
	cases := []struct {
		addr   string
		public bool
	}{
		{":8443", true},
		{"0.0.0.0:8443", true},
		{"[::]:8443", true},
		{"192.168.1.10:8443", true},
		{"127.0.0.1:8443", false},
		{"localhost:8443", false},
		{"[::1]:8443", false},
	}

	for _, tc := range cases {
		cfg := config.Defaults()
		cfg.Web.Listen = tc.addr

		if got := cfg.PortalIsPublic(); got != tc.public {
			t.Errorf("PortalIsPublic(%q) = %v, want %v", tc.addr, got, tc.public)
		}
	}
}

// A listen address that is not host:port must be caught at startup, not when
// the socket fails to bind.
func TestMalformedListenAddressesAreRefused(t *testing.T) {
	for _, addr := range []string{"8443", "not-real", ""} {
		cfg := config.Defaults()
		cfg.Web.Listen = addr

		err := cfg.Validate()
		if err == nil {
			t.Errorf("web.listen %q was accepted", addr)
			continue
		}
		if !strings.Contains(err.Error(), "web.listen") {
			t.Errorf("web.listen %q was refused for the wrong reason: %v", addr, err)
		}
	}
}

// Binding the portal to loopback stays possible for anyone who prefers a
// tunnel; it just is not the default any more.
func TestLoopbackPortalIsStillAllowed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Web.Listen = "127.0.0.1:8443"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a loopback portal was refused: %v", err)
	}
}

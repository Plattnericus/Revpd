package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/config"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "revpd.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	if err := config.Defaults().Validate(); err != nil {
		t.Fatalf("shipped defaults do not validate: %v", err)
	}
}

// JIT leans on an unauthenticated hint, so it must never come on by itself.
func TestJITIsOffByDefault(t *testing.T) {
	if config.Defaults().JIT.Enabled {
		t.Fatal("jit is enabled by default; it must be opt-in")
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	p := write(t, `
data_dir: /srv/revpd
web:
  hostname: gw.example.com
grant:
  ttl: 90s
`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.DataDir != "/srv/revpd" {
		t.Fatalf("data_dir = %q", cfg.DataDir)
	}
	if cfg.Grant.TTL != 90*time.Second {
		t.Fatalf("grant.ttl = %v, want 90s", cfg.Grant.TTL)
	}
	// Untouched keys must keep their defaults.
	if cfg.Relay.Listen != ":3389" {
		t.Fatalf("relay.listen = %q, want the default :3389", cfg.Relay.Listen)
	}
}

// A typo in a security setting must fail loudly, not get silently ignored.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := write(t, `
web:
  hostname: gw.example.com
grant:
  tttl: 90s
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("typo in a config key was accepted")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		want string
		edit func(*config.Config)
	}{
		{"empty hostname", "web.hostname", func(c *config.Config) { c.Web.Hostname = "" }},
		{"zero grant ttl", "grant.ttl", func(c *config.Config) { c.Grant.TTL = 0 }},
		{"absurd grant ttl", "grant.ttl", func(c *config.Config) { c.Grant.TTL = 2 * time.Hour }},
		{"wide ipv4 prefix", "ipv4_prefix_bits", func(c *config.Config) { c.Grant.IPv4PrefixBits = 8 }},
		{"wide totp skew", "totp_skew", func(c *config.Config) { c.Auth.TOTPSkew = 5 }},
		{"no failure cap", "max_failures", func(c *config.Config) { c.Auth.MaxFailures = 0 }},
		{"half a tls pair", "tls_cert", func(c *config.Config) { c.Web.TLSCert = "/x.pem" }},
		{"listen without a port", "web.listen", func(c *config.Config) { c.Web.Listen = "8443" }},
		{"relay listen without a port", "relay.listen", func(c *config.Config) { c.Relay.Listen = "3389" }},
		{"jit without hold", "hold_timeout", func(c *config.Config) {
			c.JIT.Enabled = true
			c.JIT.HoldTimeout = 0
		}},
		{"notifications with nowhere to send", "notify.url", func(c *config.Config) {
			c.Notify.Enabled = true
			c.Notify.URL = ""
		}},
		{"notification url over plain http", "notify.url", func(c *config.Config) {
			c.Notify.URL = "http://ntfy.sh/alerts"
		}},
		{"unknown notification format", "notify.format", func(c *config.Config) {
			c.Notify.Format = "telegram"
		}},
		{"notification event that does not exist", "notify.events", func(c *config.Config) {
			c.Notify.Events = []string{"relay.opened"}
		}},
		{"notifications with nothing to report", "notify.events", func(c *config.Config) {
			c.Notify.Enabled = true
			c.Notify.URL = "https://ntfy.sh/alerts"
			c.Notify.Events = nil
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			tc.edit(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

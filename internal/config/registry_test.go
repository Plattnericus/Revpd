package config

import (
	"strings"
	"testing"
	"time"
)

func base(t *testing.T) Config {
	t.Helper()
	c := Defaults()
	c.Web.Hostname = "gw.example.com"
	return c
}

/* ------------------------------------------------------------- the list --- */

// Every entry has to be usable by an interface that knows nothing about it:
// a key, a group it belongs to, a control to draw, and a value it can read.
func TestEveryEntryIsWellFormed(t *testing.T) {
	cfg := base(t)
	seen := map[string]bool{}
	groups := map[Group]bool{}
	for _, g := range Groups {
		groups[g] = true
	}

	for _, s := range Registry() {
		if s.Key == "" {
			t.Fatal("a setting has no key")
		}
		if seen[s.Key] {
			t.Errorf("%s appears twice", s.Key)
		}
		seen[s.Key] = true

		if !groups[s.Group] {
			t.Errorf("%s is in group %q, which is not on the settings page", s.Key, s.Group)
		}
		if s.get == nil || s.set == nil {
			t.Fatalf("%s cannot be read or written", s.Key)
		}

		// Reading and writing back the same value must be a no-op. A getter
		// and setter that disagree would quietly corrupt a save.
		before := s.Value(cfg)
		out := cfg
		if err := s.set(&out, before); err != nil {
			t.Errorf("%s rejected its own current value %q: %v", s.Key, before, err)
			continue
		}
		if after := s.Value(out); after != before {
			t.Errorf("%s round-trips wrong: read %q, wrote it back, read %q", s.Key, before, after)
		}

		if s.Kind == KindInt || s.Kind == KindDuration {
			if s.Max <= s.Min {
				t.Errorf("%s has an empty range %d..%d", s.Key, s.Min, s.Max)
			}
		}
	}
}

// The shipped defaults must sit inside the bounds the interface enforces, or a
// fresh install shows values it would refuse to accept.
func TestDefaultsFitTheirOwnBounds(t *testing.T) {
	cfg := base(t)

	for _, s := range Registry() {
		if s.Kind != KindInt && s.Kind != KindDuration {
			continue
		}
		out := cfg
		if err := s.set(&out, s.Value(cfg)); err != nil {
			t.Errorf("the default for %s is outside its own range: %v", s.Key, err)
		}
	}
}

/* -------------------------------------------------------------- applying -- */

func TestApplyLayersOverrides(t *testing.T) {
	got, unknown, err := Apply(base(t), map[string]string{
		"web.listen":        ":8443",
		"grant.ttl":         "300",
		"auth.max_failures": "9",
		"jit.enabled":       "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Errorf("unexpected unknown keys: %v", unknown)
	}

	if got.Web.Listen != ":8443" {
		t.Errorf("web.listen = %q", got.Web.Listen)
	}
	if got.Grant.TTL != 5*time.Minute {
		t.Errorf("grant.ttl = %s, want 5m", got.Grant.TTL)
	}
	if got.Auth.MaxFailures != 9 {
		t.Errorf("auth.max_failures = %d", got.Auth.MaxFailures)
	}
	if !got.JIT.Enabled {
		t.Error("jit.enabled did not take")
	}
}

// The registry deliberately owns no rules of its own. This is the proof: a
// value inside the field's own range but forbidden by Validate has to be
// refused, and refused by Validate's words.
func TestApplyDefersToValidate(t *testing.T) {
	// grant.ttl above 30 minutes is rejected by Validate as defeating the
	// point of MFA. The field's bound stops at exactly 30 minutes, so this
	// reaches Validate rather than the range check.
	_, _, err := Apply(base(t), map[string]string{"grant.ttl": "1800"})
	if err != nil {
		t.Fatalf("30m should be allowed: %v", err)
	}

	// Turning off both ways in is something only Validate knows about: each
	// setting is individually fine.
	_, _, err = Apply(base(t), map[string]string{
		"rdp_login.enabled": "false",
		"jit.enabled":       "false",
	})
	if err == nil {
		t.Fatal("accepted a configuration with no way to connect")
	}
	if !strings.Contains(err.Error(), "rdp_login") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// A save is judged as a whole. Applying one key at a time would reject a pair
// of changes that are only valid together.
func TestApplyJudgesTheWholeSetAtOnce(t *testing.T) {
	// Alone, this is invalid — checking every 60s exhausts GitHub's limit.
	if _, _, err := Apply(base(t), map[string]string{"update.check_interval": "60"}); err == nil {
		t.Fatal("a 60s check interval was accepted on its own")
	}

	// Together with turning checking off, it is allowed: the interval no
	// longer has any effect.
	if _, _, err := Apply(base(t), map[string]string{
		"update.check_interval": "60",
		"update.enabled":        "false",
	}); err != nil {
		t.Fatalf("the pair should be accepted together: %v", err)
	}
}

// A rejected save must leave the running configuration untouched — not
// half-applied up to the offending key.
func TestApplyChangesNothingWhenItFails(t *testing.T) {
	start := base(t)

	got, _, err := Apply(start, map[string]string{
		"auth.max_failures": "7",      // fine
		"grant.ttl":         "999999", // out of range
	})
	if err == nil {
		t.Fatal("accepted an out-of-range value")
	}
	if got.Auth.MaxFailures != start.Auth.MaxFailures {
		t.Error("the valid half of a rejected save was applied anyway")
	}
	if got.Grant.TTL != start.Grant.TTL {
		t.Error("the running configuration was modified by a failed save")
	}
}

// A setting dropped in an upgrade leaves a stored value behind. That must be
// reported but must never stop the gateway from starting.
func TestApplyReportsUnknownKeysWithoutFailing(t *testing.T) {
	got, unknown, err := Apply(base(t), map[string]string{
		"web.listen":        ":8443",
		"something.removed": "1",
	})
	if err != nil {
		t.Fatalf("a stale key stopped startup: %v", err)
	}
	if len(unknown) != 1 || unknown[0] != "something.removed" {
		t.Errorf("unknown = %v, want [something.removed]", unknown)
	}
	if got.Web.Listen != ":8443" {
		t.Error("the valid keys were not applied")
	}
}

/* --------------------------------------------------------------- values --- */

func TestRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		key, value, wants string
	}{
		{"web.listen", "443", "address like"},
		{"web.listen", ":not-a-port", "port number"},
		{"web.listen", ":70000", "port number"},
		{"relay.listen", "hello", "address like"},
		{"auth.max_failures", "many", "whole number"},
		{"auth.max_failures", "0", "outside the allowed range"},
		{"auth.max_failures", "500", "outside the allowed range"},
		{"grant.ttl", "2", "outside the allowed range"}, // below anything workable
		{"auth.totp_skew", "99", "outside the allowed range"},
		{"jit.enabled", "maybe", "not on or off"},
		{"web.listen_fallbacks", ":8443, nonsense", "address like"},
	}

	for _, c := range cases {
		s, ok := Lookup(c.key)
		if !ok {
			t.Fatalf("no setting %q", c.key)
		}
		cfg := base(t)
		err := s.set(&cfg, c.value)
		if err == nil {
			t.Errorf("%s accepted %q", c.key, c.value)
			continue
		}
		if !strings.Contains(err.Error(), c.wants) {
			t.Errorf("%s = %q: error %q does not mention %q", c.key, c.value, err, c.wants)
		}
	}
}

func TestAddressListRoundTrips(t *testing.T) {
	s, _ := Lookup("web.listen_fallbacks")
	cfg := base(t)

	if err := s.set(&cfg, " :8443 ,:9443,, "); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Web.ListenFallbacks) != 2 {
		t.Fatalf("got %v, want two addresses with the blanks dropped", cfg.Web.ListenFallbacks)
	}
	if got := s.Value(cfg); got != ":8443, :9443" {
		t.Errorf("reads back as %q", got)
	}
}

// An optional listener has to be closable, and Validate has to still accept it.
func TestHTTPRedirectCanBeTurnedOff(t *testing.T) {
	got, _, err := Apply(base(t), map[string]string{"web.http_listen": ""})
	if err != nil {
		t.Fatalf("closing the redirect port was refused: %v", err)
	}
	if got.Web.HTTPListen != "" {
		t.Errorf("http_listen = %q, want empty", got.Web.HTTPListen)
	}
}

/* -------------------------------------------------------------- restart --- */

// Anything read once while starting up has to be marked, or the interface
// reports a change as live when it has not taken effect at all.
func TestSettingsReadAtStartupAreMarked(t *testing.T) {
	mustRestart := []string{
		"web.listen", "web.listen_fallbacks", "web.http_listen", "web.hostname",
		"relay.listen", "relay.tarpit", "relay.max_conns_per_ip",
		"grant.ttl", "auth.session_ttl", "auth.max_failures",
		"rdp_login.enabled", "jit.enabled", "wol.repeat",
		"update.enabled", "update.check_interval",
	}

	for _, key := range mustRestart {
		s, ok := Lookup(key)
		if !ok {
			t.Errorf("no setting %q", key)
			continue
		}
		if !s.NeedsRestart() {
			t.Errorf("%s is read at startup but is not marked as needing a restart", key)
		}
	}

	// And the ones that really do take immediately must not ask for one.
	for _, key := range []string{"update.auto_install", "update.only_when_idle"} {
		s, ok := Lookup(key)
		if !ok {
			t.Errorf("no setting %q", key)
			continue
		}
		if s.NeedsRestart() {
			t.Errorf("%s takes effect immediately but demands a restart", key)
		}
	}
}

// Nothing that would hand control of the machine to whoever is signed in to
// the portal belongs in here.
func TestDangerousSettingsAreNotEditable(t *testing.T) {
	for _, key := range []string{
		"data_dir",            // would move the database out from under it
		"auth.master_key_env", // would point at an attacker-chosen key
		"web.tls_cert",        // reads a file path as the service account
		"web.tls_key",
		"web.trusted_proxies", // would let anyone spoof their source address
		"rdgw.enabled",
	} {
		if _, ok := Lookup(key); ok {
			t.Errorf("%s can be changed from the web interface; it should not be", key)
		}
	}
}

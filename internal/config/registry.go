package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
	Which settings can be changed from the web interface, and what a valid
	value looks like.

	Two rules shape this file.

	The first is that nothing here re-implements validation. A change is
	applied to a *copy* of the running configuration and that copy is handed to
	Validate() — the same function that guards revpd.yaml at startup. A rule
	added there is enforced here for free, and the two can never disagree about
	what is allowed.

	The second is that the file on disk stays readable. Overrides live in the
	database because the service runs with /etc mounted read-only, so revpd.yaml
	is never rewritten behind anyone's back. Both values are reported, and a
	setting can always be handed back to the file.
*/

// Kind tells the interface what control to draw and how to read the value back.
type Kind string

const (
	KindBool     Kind = "bool"
	KindInt      Kind = "int"
	KindDuration Kind = "duration" // carried as whole seconds
	KindText     Kind = "text"
	KindAddr     Kind = "addr"      // host:port
	KindAddrList Kind = "addr_list" // comma-separated host:port
	KindTextList Kind = "text_list" // comma-separated free text
)

// Group is how the settings page is divided. Ordered as they should appear.
type Group string

const (
	GroupPublic  Group = "public"
	GroupNetwork Group = "network"
	GroupAccess  Group = "access"
	GroupSignIn  Group = "signin"
	GroupRelay   Group = "relay"
	GroupDesktop Group = "desktop"
	GroupWake    Group = "wake"
	GroupUpdates Group = "updates"
)

// Groups in display order.
var Groups = []Group{
	GroupPublic, GroupNetwork, GroupAccess, GroupSignIn, GroupRelay, GroupDesktop, GroupWake, GroupUpdates,
}

// Setting is one editable value.
type Setting struct {
	Key   string
	Group Group
	Kind  Kind

	// Restart reports whether the value is only read while starting up. A
	// listener cannot move under a running server and a certificate cannot be
	// swapped mid-handshake, so those are marked and the interface offers a
	// restart rather than pretending the change already took.
	Restart bool

	// Min and Max are structural bounds only: what the field can physically
	// hold. Every rule about what makes *sense* — a grant longer than half an
	// hour, a check interval that would exhaust GitHub's rate limit — stays in
	// Validate, which sees the whole configuration and can say why.
	//
	// Duplicating a rule here would be worse than redundant. Validate's version
	// of several of them is conditional, and a flat bound would forbid
	// combinations that are perfectly valid.
	Min, Max int64

	// Warn is shown next to the field when changing it has a consequence that
	// is not obvious from its name.
	Warn string

	get func(*Config) string
	set func(*Config, string) error
}

// Registry is every setting the interface may change, in display order.
//
// Anything absent is deliberately absent: paths, the master key variable and
// the TLS certificate locations belong to whoever installed the machine, not
// to whoever is signed in to the portal.
func Registry() []Setting {
	return []Setting{
		/* -------------------------------------------------------- public --- */

		// None of these move a listener or touch a certificate: they describe
		// what is already true on the far side of the router. So they take
		// effect the moment they are saved rather than asking for a restart
		// that would drop every open desktop session to change a printed
		// address.
		host("public.host", GroupPublic, false, func(c *Config) *string { return &c.Public.Host },
			"The domain or address you reach this gateway on from outside. Leave it empty to use the detected address."),
		boolean("public.detect", GroupPublic, false, func(c *Config) *bool { return &c.Public.Detect },
			"Ask the internet what address it sees. Turn it off and nothing is ever told about this gateway; only the host above is used."),
		port("public.rdp_port", GroupPublic, false, func(c *Config) *int { return &c.Public.RDPPort },
			"The port your router forwards to Remote Desktop. Leave it at 0 when the router passes the same number straight through."),
		port("public.portal_port", GroupPublic, false, func(c *Config) *int { return &c.Public.PortalPort },
			"The same for the web interface."),
		textList("public.resolvers", GroupPublic, true, func(c *Config) *[]string { return &c.Public.Resolvers },
			"Where to ask. HTTPS only, and two have to agree before an answer is used."),
		duration("public.refresh", GroupPublic, true, 300, 7*24*3600, func(c *Config) *time.Duration { return &c.Public.Refresh },
			"How often to look again. Home connections change address without warning."),

		/* ------------------------------------------------------- network --- */

		addr("web.listen", GroupNetwork, true, func(c *Config) *string { return &c.Web.Listen },
			"Moving the portal changes the address everyone types, and the port has to be forwarded to match."),
		addrList("web.listen_fallbacks", GroupNetwork, true, func(c *Config) *[]string { return &c.Web.ListenFallbacks },
			"Tried in order when the port above is already taken."),
		addr("web.http_listen", GroupNetwork, true, func(c *Config) *string { return &c.Web.HTTPListen },
			"Answers plain HTTP with a redirect to the portal. Leave empty to close it."),
		addrList("web.http_listen_fallbacks", GroupNetwork, true, func(c *Config) *[]string { return &c.Web.HTTPListenFallbacks }, ""),
		text("web.hostname", GroupNetwork, true, func(c *Config) *string { return &c.Web.Hostname },
			"Also the WebAuthn identifier: changing it invalidates every passkey that has been enrolled."),
		addr("relay.listen", GroupNetwork, true, func(c *Config) *string { return &c.Relay.Listen },
			"Where Remote Desktop connects. 3389 is what clients assume when no port is typed."),

		/* -------------------------------------------------------- access --- */

		duration("grant.ttl", GroupAccess, true, 5, 24*3600, func(c *Config) *time.Duration { return &c.Grant.TTL },
			"How long there is to start Remote Desktop after passing the second factor."),
		duration("grant.reuse_window", GroupAccess, true, 0, 24*3600, func(c *Config) *time.Duration { return &c.Grant.ReuseWindow },
			"A reconnect within this window is let through without asking for the code again."),
		integer("grant.ipv4_prefix_bits", GroupAccess, true, 16, 32, func(c *Config) *int { return &c.Grant.IPv4PrefixBits },
			"32 ties a grant to one exact address. Lower it only for networks that move you between addresses."),
		integer("grant.ipv6_prefix_bits", GroupAccess, true, 32, 128, func(c *Config) *int { return &c.Grant.IPv6PrefixBits }, ""),

		/* ------------------------------------------------------- sign-in --- */

		duration("auth.session_ttl", GroupSignIn, true, 300, 30*24*3600, func(c *Config) *time.Duration { return &c.Auth.SessionTTL }, ""),
		duration("auth.session_idle", GroupSignIn, true, 60, 7*24*3600, func(c *Config) *time.Duration { return &c.Auth.SessionIdle },
			"A session left untouched for this long has to sign in again."),
		integer("auth.max_failures", GroupSignIn, true, 1, 100, func(c *Config) *int { return &c.Auth.MaxFailures },
			"Failures beyond this lock the account for a while, doubling each time."),
		duration("auth.lockout_base", GroupSignIn, true, 1, 3600, func(c *Config) *time.Duration { return &c.Auth.LockoutBase }, ""),
		duration("auth.lockout_max", GroupSignIn, true, 60, 30*24*3600, func(c *Config) *time.Duration { return &c.Auth.LockoutMax }, ""),
		unsigned("auth.totp_skew", GroupSignIn, true, 0, 10, func(c *Config) *uint { return &c.Auth.TOTPSkew },
			"Extra 30-second steps accepted either side of now. Higher forgives a wrong clock but widens the replay window."),
		boolean("auth.require_second_factor", GroupSignIn, true, func(c *Config) *bool { return &c.Auth.RequireSecondFactor },
			"Strongly recommended. With this off, an account that has enrolled nothing can sign in with its password alone — and a stolen password is then enough to wake a machine and open a desktop session."),
		integer("auth.backup_codes", GroupSignIn, true, 0, 100, func(c *Config) *int { return &c.Auth.BackupCodes },
			"How many one-time codes a new enrolment hands out."),

		/* --------------------------------------------------------- relay --- */

		duration("relay.tarpit", GroupRelay, true, 0, 120, func(c *Config) *time.Duration { return &c.Relay.Tarpit },
			"How long a rejected scanner is held before the connection closes."),
		integer("relay.max_conns_per_ip", GroupRelay, true, 1, 1000, func(c *Config) *int { return &c.Relay.MaxConnsPerIP }, ""),
		duration("relay.dial_timeout", GroupRelay, true, 1, 300, func(c *Config) *time.Duration { return &c.Relay.DialTimeout }, ""),
		duration("relay.idle_timeout", GroupRelay, true, 60, 24*3600, func(c *Config) *time.Duration { return &c.Relay.IdleTimeout },
			"An open desktop session with no traffic for this long is closed."),

		/* ------------------------------------------------------- desktop --- */

		boolean("rdp_login.enabled", GroupDesktop, true, func(c *Config) *bool { return &c.RDPLogin.Enabled },
			"Signing in from the Remote Desktop client itself, password and code separated by a comma. This is how people normally connect."),
		boolean("rdp_login.pass_through_credentials", GroupDesktop, true, func(c *Config) *bool { return &c.RDPLogin.PassThroughCredentials },
			"Hand the password on to Windows so it is typed once. Off means Windows asks again."),
		duration("rdp_login.timeout", GroupDesktop, true, 30, 900, func(c *Config) *time.Duration { return &c.RDPLogin.Timeout },
			"Budget for the whole sign-in, including waiting for the machine to boot."),
		duration("rdp_login.step_timeout", GroupDesktop, true, 5, 300, func(c *Config) *time.Duration { return &c.RDPLogin.StepTimeout }, ""),
		boolean("jit.enabled", GroupDesktop, true, func(c *Config) *bool { return &c.JIT.Enabled },
			"Hold the connection while a push approval is answered. Off by default because it acts on an unauthenticated hint."),
		duration("jit.hold_timeout", GroupDesktop, true, 5, 300, func(c *Config) *time.Duration { return &c.JIT.HoldTimeout }, ""),

		/* ---------------------------------------------------------- wake --- */

		duration("wol.probe_interval", GroupWake, true, 0, 60, func(c *Config) *time.Duration { return &c.WoL.ProbeInterval },
			"How often to check whether the machine has finished booting."),
		duration("wol.probe_settle", GroupWake, true, 0, 120, func(c *Config) *time.Duration { return &c.WoL.ProbeSettle },
			"Windows answers on the network card a moment before Remote Desktop is ready. This waits it out."),
		integer("wol.repeat", GroupWake, true, 1, 10, func(c *Config) *int { return &c.WoL.Repeat },
			"How many magic packets to send. More than one covers a dropped datagram."),

		/* ------------------------------------------------------- updates --- */

		boolean("update.enabled", GroupUpdates, true, func(c *Config) *bool { return &c.Update.Enabled },
			"Check GitHub for newer releases on a timer."),
		boolean("update.auto_install", GroupUpdates, false, func(c *Config) *bool { return &c.Update.AutoInstall },
			"Install them without being asked. Takes effect immediately."),
		boolean("update.only_when_idle", GroupUpdates, false, func(c *Config) *bool { return &c.Update.OnlyWhenIdle },
			"Wait for nobody to be connected before an automatic install restarts the service."),
		boolean("update.prerelease", GroupUpdates, true, func(c *Config) *bool { return &c.Update.Prerelease },
			"Accept release candidates as well as final releases."),
		duration("update.check_interval", GroupUpdates, true, 1, 7*24*3600, func(c *Config) *time.Duration { return &c.Update.CheckInterval },
			"Below fifteen minutes GitHub's rate limit runs out."),
		text("update.repo", GroupUpdates, true, func(c *Config) *string { return &c.Update.Repo },
			"Where releases come from, as owner/name. Empty follows the repository this build came from."),
	}
}

// Lookup finds one setting by key.
func Lookup(key string) (Setting, bool) {
	for _, s := range Registry() {
		if s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// Value reads the setting's current value out of a configuration, as the text
// the interface exchanges.
func (s Setting) Value(c Config) string { return s.get(&c) }

// NeedsRestart reports whether changing this takes a restart to have an effect.
func (s Setting) NeedsRestart() bool { return s.Restart }

/* ------------------------------------------------------------- applying --- */

// Apply layers stored overrides onto a configuration and validates the result.
//
// The whole set is applied before anything is checked, because settings
// constrain each other: raising a maximum and a minimum in one save has to be
// judged together, not one at a time.
//
// Unknown keys are reported rather than ignored. They mean a setting was
// removed in an upgrade and the stored value is now dead weight — worth
// knowing about, but never a reason to refuse to start.
func Apply(base Config, overrides map[string]string) (Config, []string, error) {
	out := base
	var unknown []string

	// Sorted so a failure is reported the same way twice running.
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		s, ok := Lookup(key)
		if !ok {
			unknown = append(unknown, key)
			continue
		}
		if err := s.set(&out, overrides[key]); err != nil {
			return base, unknown, fmt.Errorf("%s: %w", key, err)
		}
	}

	if err := out.Validate(); err != nil {
		return base, unknown, err
	}
	return out, unknown, nil
}

/* -------------------------------------------------------- constructors --- */

func boolean(key string, g Group, restart bool, ptr func(*Config) *bool, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindBool, Restart: restart, Warn: warn,
		get: func(c *Config) string { return strconv.FormatBool(*ptr(c)) },
		set: func(c *Config, v string) error {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%q is not on or off", v)
			}
			*ptr(c) = b
			return nil
		},
	}
}

func integer(key string, g Group, restart bool, min, max int64, ptr func(*Config) *int, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindInt, Restart: restart, Min: min, Max: max, Warn: warn,
		get: func(c *Config) string { return strconv.Itoa(*ptr(c)) },
		set: func(c *Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%q is not a whole number", v)
			}
			if int64(n) < min || int64(n) > max {
				return fmt.Errorf("%d is outside the allowed range %d to %d", n, min, max)
			}
			*ptr(c) = n
			return nil
		},
	}
}

// duration carries whole seconds over the wire: a number with a unit beside it
// is easier to get right in a form than a string like "2m30s", and it cannot
// be mistyped into something that parses but means something else.
func duration(key string, g Group, restart bool, minSec, maxSec int64, ptr func(*Config) *time.Duration, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindDuration, Restart: restart, Min: minSec, Max: maxSec, Warn: warn,
		get: func(c *Config) string {
			return strconv.FormatInt(int64((*ptr(c)).Seconds()), 10)
		},
		set: func(c *Config, v string) error {
			secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a number of seconds", v)
			}
			if secs < minSec || secs > maxSec {
				return fmt.Errorf("%ds is outside the allowed range %ds to %ds", secs, minSec, maxSec)
			}
			*ptr(c) = time.Duration(secs) * time.Second
			return nil
		},
	}
}

func text(key string, g Group, restart bool, ptr func(*Config) *string, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindText, Restart: restart, Warn: warn,
		get: func(c *Config) string { return *ptr(c) },
		set: func(c *Config, v string) error {
			*ptr(c) = strings.TrimSpace(v)
			return nil
		},
	}
}

// host accepts a bare hostname or address, and refuses the two things people
// reach for instead — a scheme in front and a port on the end.
func host(key string, g Group, restart bool, ptr func(*Config) *string, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindText, Restart: restart, Warn: warn,
		get: func(c *Config) string { return *ptr(c) },
		set: func(c *Config, v string) error {
			v = strings.TrimSpace(v)
			if err := CheckPublicHost(v); err != nil {
				return err
			}
			*ptr(c) = v
			return nil
		},
	}
}

// port is a port number, with zero meaning "whatever the listener uses".
func port(key string, g Group, restart bool, ptr func(*Config) *int, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindInt, Restart: restart, Min: 0, Max: 65535, Warn: warn,
		get: func(c *Config) string { return strconv.Itoa(*ptr(c)) },
		set: func(c *Config, v string) error {
			v = strings.TrimSpace(v)
			if v == "" {
				v = "0" // an emptied field reads as "same as the listener"
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("%q is not a port number", v)
			}
			if n < 0 || n > 65535 {
				return fmt.Errorf("%d is not a port number", n)
			}
			*ptr(c) = n
			return nil
		},
	}
}

// textList is a comma-separated list of things that are not addresses. What
// counts as valid is Validate's business, which knows what the list is for.
func textList(key string, g Group, restart bool, ptr func(*Config) *[]string, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindTextList, Restart: restart, Warn: warn,
		get: func(c *Config) string { return strings.Join(*ptr(c), ", ") },
		set: func(c *Config, v string) error {
			var list []string
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); part != "" {
					list = append(list, part)
				}
			}
			*ptr(c) = list
			return nil
		},
	}
}

// addr accepts host:port, and an empty value where the listener is optional.
// The shape is checked here; whether it is allowed to be empty is Validate's
// business, which already knows which listeners are required.
func addr(key string, g Group, restart bool, ptr func(*Config) *string, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindAddr, Restart: restart, Warn: warn,
		get: func(c *Config) string { return *ptr(c) },
		set: func(c *Config, v string) error {
			v = strings.TrimSpace(v)
			if v != "" {
				if err := checkAddr(v); err != nil {
					return err
				}
			}
			*ptr(c) = v
			return nil
		},
	}
}

func addrList(key string, g Group, restart bool, ptr func(*Config) *[]string, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindAddrList, Restart: restart, Warn: warn,
		get: func(c *Config) string { return strings.Join(*ptr(c), ", ") },
		set: func(c *Config, v string) error {
			var list []string
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				if err := checkAddr(part); err != nil {
					return err
				}
				list = append(list, part)
			}
			*ptr(c) = list
			return nil
		},
	}
}

// unsigned is integer for the one field that is a uint. Separate rather than
// converted through a pointer, because a *uint cannot masquerade as a *int and
// a shim that copied the value would silently drop the write.
func unsigned(key string, g Group, restart bool, min, max int64, ptr func(*Config) *uint, warn string) Setting {
	return Setting{
		Key: key, Group: g, Kind: KindInt, Restart: restart, Min: min, Max: max, Warn: warn,
		get: func(c *Config) string { return strconv.FormatUint(uint64(*ptr(c)), 10) },
		set: func(c *Config, v string) error {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a whole number", v)
			}
			if n < min || n > max {
				return fmt.Errorf("%d is outside the allowed range %d to %d", n, min, max)
			}
			*ptr(c) = uint(n)
			return nil
		},
	}
}

func checkAddr(v string) error {
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%q is not an address like :443 or 127.0.0.1:8443", v)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has no usable port number", v)
	}
	return nil
}

// Package config loads and validates revpd.yaml.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/plattnericus/revpd/internal/netcheck"
	"github.com/plattnericus/revpd/internal/notify"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string `yaml:"data_dir"`

	Web      Web      `yaml:"web"`
	Public   Public   `yaml:"public"`
	Relay    Relay    `yaml:"relay"`
	Grant    Grant    `yaml:"grant"`
	RDPLogin RDPLogin `yaml:"rdp_login"`
	JIT      JIT      `yaml:"jit"`
	WoL      WoL      `yaml:"wol"`
	Auth     Auth     `yaml:"auth"`
	RDGW     RDGW     `yaml:"rdgw"`
	Notify   Notify   `yaml:"notify"`
	Update   Update   `yaml:"update"`
}

type Web struct {
	// Listen is the portal. Together with relay.listen these are the only two
	// ports that face the internet; nothing else is opened.
	//
	// The portal always speaks TLS. Leaving tls_cert empty means a self-signed
	// certificate is generated rather than falling back to plain HTTP, so a
	// session cookie is never handed out in the clear.
	Listen string `yaml:"listen"`

	// ListenFallbacks are tried in order when Listen is already taken.
	//
	// 443 is what people expect to type, but on a machine that already runs a
	// web server it is spoken for. Refusing to start would be correct and
	// useless; moving to the next port and saying so is neither.
	ListenFallbacks []string `yaml:"listen_fallbacks"`

	// HTTPListen answers plain HTTP with a permanent redirect to the portal,
	// so somebody who types the hostname without https:// still arrives.
	// It serves nothing else. Empty turns it off.
	HTTPListen string `yaml:"http_listen"`

	HTTPListenFallbacks []string `yaml:"http_listen_fallbacks"`

	// External name users type into the browser. Also the WebAuthn relying-party ID,
	// so changing it invalidates every enrolled passkey.
	Hostname string `yaml:"hostname"`

	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	ACME    bool   `yaml:"acme"`

	// Set only when something like nginx sits in front. Trusting these blindly
	// would let anyone spoof their source IP and steal a grant.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// Public describes the gateway as the internet sees it, which is never what
// the listening sockets see.
//
// Behind a router the sockets only know the LAN: the address people actually
// type, and the port the router forwards, both live on the far side of the
// NAT. Everything here exists to close that gap — so the portal can say "point
// Remote Desktop at this" and be right.
//
// None of it is ever consulted to decide whether a connection may proceed.
// Some of it comes from a third party, and a third party can lie.
type Public struct {
	// Host is the domain or address people type. A bare name or address, no
	// scheme and no port — the ports below cover the forwarding.
	//
	// Set this and it wins over anything detected, which is what a fixed
	// domain or a dynamic-DNS name is for. Leave it empty and the detected
	// address is used instead.
	Host string `yaml:"host"`

	// Detect asks the outside world what address it sees. Off means the
	// gateway never mentions itself to a third party, and only Host is used.
	//
	// A machine with a public address on one of its own interfaces — any VPS —
	// is answered from the interface and nobody is asked either way.
	Detect bool `yaml:"detect"`

	// Resolvers answer with the caller's address and nothing else. Asked in
	// parallel, and two have to agree before an answer is believed, so one
	// endpoint going bad cannot move the result on its own.
	//
	// HTTPS only. Over plain HTTP anyone on the path could choose the address
	// the portal then hands out.
	Resolvers []string `yaml:"resolvers"`

	// Refresh is how often to look again. Home connections change address, so
	// this is not a startup-only question.
	Refresh time.Duration `yaml:"refresh"`

	// RDPPort is the port on the router that forwards to relay.listen. Zero
	// means it forwards the same number through, which is the usual case.
	//
	// It exists because the two need not match: forwarding some high port to
	// 3389 keeps the internet's background scan of 3389 off the door, and the
	// address the portal prints has to say so.
	RDPPort int `yaml:"rdp_port"`

	// PortalPort is the same idea for the web interface.
	PortalPort int `yaml:"portal_port"`
}

type Relay struct {
	Listen string `yaml:"listen"`

	// Slow-drip bytes at rejected scanners instead of closing instantly.
	Tarpit time.Duration `yaml:"tarpit"`

	MaxConnsPerIP int           `yaml:"max_conns_per_ip"`
	DialTimeout   time.Duration `yaml:"dial_timeout"`
	IdleTimeout   time.Duration `yaml:"idle_timeout"`
}

type Grant struct {
	// How long the user has to actually launch mstsc after passing MFA.
	TTL time.Duration `yaml:"ttl"`

	// mstsc reconnects after a network blip. Without this window every WLAN
	// handover would demand a fresh MFA round.
	ReuseWindow time.Duration `yaml:"reuse_window"`

	// Mobile networks hop addresses within a carrier block. Widening the match
	// trades a little security for far fewer failed connects.
	IPv4PrefixBits int `yaml:"ipv4_prefix_bits"`
	IPv6PrefixBits int `yaml:"ipv6_prefix_bits"`
}

// RDPLogin is the standard way in: the user types their password and one-time
// code straight into the Windows Remote Desktop client, and the gateway sends
// them on with a Server Redirection.
type RDPLogin struct {
	Enabled bool `yaml:"enabled"`

	// Certificate the RDP listener presents. Leave empty and a self-signed one
	// is generated into data_dir — the same thing a stock Windows host does.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`

	// Budget for the whole login, including waiting for the machine to boot.
	Timeout time.Duration `yaml:"timeout"`

	// Budget for a single step, so a stalled client cannot hold a slot.
	StepTimeout time.Duration `yaml:"step_timeout"`

	// Hand the password on to Windows so the user types it only once. Turning
	// this off means Windows asks again over NLA and the gateway never sees
	// the credentials in a form it could pass along.
	PassThroughCredentials bool `yaml:"pass_through_credentials"`
}

type JIT struct {
	Enabled bool `yaml:"enabled"`

	// How long we hold the TCP connection while waiting for the push approval.
	// mstsc's patience is not specified anywhere; 45s measured fine, tune per site.
	HoldTimeout time.Duration `yaml:"hold_timeout"`

	// Time budget for reading the very first X.224 packet.
	PeekTimeout time.Duration `yaml:"peek_timeout"`

	MaxPendingPerIP int `yaml:"max_pending_per_ip"`

	// Target used when the client cannot tell us which machine it wants.
	DefaultTarget string `yaml:"default_target"`
}

type WoL struct {
	// Poll interval and settle delay for the readiness probe. Windows answers on
	// the NIC a beat before RDP is actually listening, hence the settle.
	ProbeInterval time.Duration `yaml:"probe_interval"`
	ProbeSettle   time.Duration `yaml:"probe_settle"`
	Repeat        int           `yaml:"repeat"`
}

type Auth struct {
	SessionTTL  time.Duration `yaml:"session_ttl"`
	SessionIdle time.Duration `yaml:"session_idle"`

	MaxFailures int           `yaml:"max_failures"`
	LockoutBase time.Duration `yaml:"lockout_base"`
	LockoutMax  time.Duration `yaml:"lockout_max"`
	TOTPSkew    uint          `yaml:"totp_skew"`

	// RequireSecondFactor decides whether an account with nothing enrolled may
	// sign in at all.
	//
	// On by default, and worth leaving on: a gateway that accepts a password
	// alone can wake a machine and open a desktop session with one stolen
	// credential, which is the thing this exists to prevent. Turning it off is
	// for the case where the password is already protected by something else,
	// or where getting started matters more than the guarantee.
	RequireSecondFactor bool   `yaml:"require_second_factor"`
	BackupCodes         int    `yaml:"backup_codes"`
	MasterKeyEnv        string `yaml:"master_key_env"`
}

type RDGW struct {
	Enabled  bool          `yaml:"enabled"`
	Listen   string        `yaml:"listen"`
	TokenTTL time.Duration `yaml:"token_ttl"`
}

// Notify sends a short message to a phone or a chat channel when something
// happens that somebody would want to know about away from the machine.
//
// Off by default. It is the one part of the gateway that talks to a service
// nobody here runs, and that should be a decision rather than a surprise.
type Notify struct {
	Enabled bool `yaml:"enabled"`

	// URL is where messages go: an ntfy topic, a Discord or Slack webhook, or
	// anything that accepts a JSON POST.
	//
	// It is a credential in its own right — whoever knows it can post to that
	// channel — which is why plain HTTP is only allowed to an address on this
	// network, and why it never appears in a log line.
	URL string `yaml:"url"`

	// Format shapes the request for the service at the other end.
	Format string `yaml:"format"`

	// Events are audit action names. The log records far more than anybody
	// wants on their phone, so this list is short by default.
	Events []string `yaml:"events"`

	Timeout time.Duration `yaml:"timeout"`
}

// Update controls how the gateway keeps itself current.
//
// Checking is on by default and costs one API call every few hours. Installing
// is not: a restart drops every live RDP session, so it stays something an
// administrator turns on knowingly — in the dashboard or here.
type Update struct {
	// Enabled turns the periodic check on. Off means the dashboard only ever
	// looks when somebody presses the button.
	Enabled bool `yaml:"enabled"`

	// Repo is owner/name. Empty derives it from the module this was built
	// from, so a fork updates from the fork with nothing to configure.
	Repo string `yaml:"repo"`

	// AutoInstall downloads and installs a new release without being asked.
	// The dashboard toggle overrides this once it has been used; this is the
	// value a fresh installation starts from.
	AutoInstall bool `yaml:"auto_install"`

	// Prerelease accepts release candidates. GitHub's "latest release" skips
	// them, so this changes which release is even considered.
	Prerelease bool `yaml:"prerelease"`

	CheckInterval time.Duration `yaml:"check_interval"`

	// OnlyWhenIdle holds an automatic install back while somebody is connected.
	// Without it an update would cut a live remote desktop session mid-sentence.
	OnlyWhenIdle bool `yaml:"only_when_idle"`
}

// Defaults returns a config that is safe to run as-is apart from hostname and TLS.
func Defaults() Config {
	return Config{
		DataDir: "/var/lib/revpd",
		Web: Web{
			// The ports a browser assumes. Binding them needs
			// CAP_NET_BIND_SERVICE, which the unit file grants and nothing
			// else — the service still runs unprivileged.
			Listen:              ":443",
			ListenFallbacks:     []string{":8443", ":9443"},
			HTTPListen:          ":80",
			HTTPListenFallbacks: []string{":8080", ":9080"},
			Hostname:            "localhost",
			ACME:                false,
		},
		Public: Public{
			Detect: true,

			// Three, so two can agree and one can be down. They answer with a
			// bare address and nothing else, which is the whole requirement.
			// Replace them with anything that does the same — including
			// something you run yourself, if asking strangers is not welcome.
			Resolvers: []string{
				"https://api.ipify.org",
				"https://icanhazip.com",
				"https://ifconfig.co/ip",
			},
			Refresh: time.Hour,
		},
		Relay: Relay{
			Listen:        ":3389",
			Tarpit:        5 * time.Second,
			MaxConnsPerIP: 8,
			DialTimeout:   10 * time.Second,
			IdleTimeout:   4 * time.Hour,
		},
		Grant: Grant{
			TTL:            2 * time.Minute,
			ReuseWindow:    10 * time.Minute,
			IPv4PrefixBits: 32, // exact match by default
			IPv6PrefixBits: 64, // /64 is one subscriber, so this is still exact enough
		},
		RDPLogin: RDPLogin{
			Enabled:                true, // this is the way users actually connect
			Timeout:                3 * time.Minute,
			StepTimeout:            30 * time.Second,
			PassThroughCredentials: true,
		},
		JIT: JIT{
			Enabled:         false, // opt-in: it relies on an unauthenticated hint
			HoldTimeout:     45 * time.Second,
			PeekTimeout:     5 * time.Second,
			MaxPendingPerIP: 3,
		},
		WoL: WoL{
			ProbeInterval: 500 * time.Millisecond,
			ProbeSettle:   2 * time.Second,
			Repeat:        3,
		},
		Auth: Auth{
			SessionTTL:          12 * time.Hour,
			SessionIdle:         30 * time.Minute,
			MaxFailures:         5,
			LockoutBase:         30 * time.Second,
			LockoutMax:          1 * time.Hour,
			TOTPSkew:            1,
			BackupCodes:         10,
			RequireSecondFactor: true,
			MasterKeyEnv:        "REVPD_MASTER_KEY",
		},
		RDGW: RDGW{
			Enabled:  false,
			Listen:   ":443",
			TokenTTL: 5 * time.Minute,
		},
		Notify: Notify{
			Enabled: false, // it reaches out to a third party; opt in first
			Format:  notify.FormatNtfy,
			Events:  notify.DefaultEvents(),
			Timeout: 10 * time.Second,
		},
		Update: Update{
			Enabled:       true,
			AutoInstall:   false, // installing restarts the service; opt in first
			Prerelease:    false,
			CheckInterval: 6 * time.Hour,
			OnlyWhenIdle:  true,
		},
	}
}

// envFileErr remembers why the secrets file could not be read, so the message
// about a missing key can name the real cause — almost always a permission
// problem, which "run it with sudo" fixes and "generate a new key" does not.
var envFileErr error

// EnvFileProblem returns why the secrets file could not be read, if it could
// not be.
func EnvFileProblem() error { return envFileErr }

func Load(path string) (Config, error) {
	cfg := Defaults()

	body, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	dec.KnownFields(true) // a typo in a security setting should fail loudly
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	// The secrets file beside it, the same one systemd hands to the service.
	// Without this every command that opens the database fails on a missing
	// master key that is sitting right there on disk.
	//
	// A failure to read it is not fatal here: the key may be in the
	// environment already, as it is in Docker. Whatever needs it says so.
	if err := LoadEnvFile(EnvFilePath(path)); err != nil {
		envFileErr = err
	}

	cfg.applyEnv()

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyEnv lets the environment win over the file, so secrets and
// host-specific values never have to be committed.
func (c *Config) applyEnv() {
	str := func(key string, dst *string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v := os.Getenv(key); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	boolean := func(key string, dst *bool) {
		switch strings.ToLower(os.Getenv(key)) {
		case "1", "true", "yes", "on":
			*dst = true
		case "0", "false", "no", "off":
			*dst = false
		}
	}
	integer := func(key string, dst *int) {
		if v := os.Getenv(key); v != "" {
			// A value that is not a number is left to Validate, which can say
			// which setting it was rather than failing silently here.
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				*dst = n
			}
		}
	}
	list := func(key string, dst *[]string) {
		v, ok := os.LookupEnv(key)
		if !ok {
			return
		}
		// An empty value clears the list rather than being ignored, so a
		// deployment can switch detection sources off from the environment.
		*dst = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				*dst = append(*dst, p)
			}
		}
	}

	str("REVPD_DATA_DIR", &c.DataDir)
	str("REVPD_WEB_LISTEN", &c.Web.Listen)
	str("REVPD_WEB_HOSTNAME", &c.Web.Hostname)
	str("REVPD_TLS_CERT", &c.Web.TLSCert)
	str("REVPD_TLS_KEY", &c.Web.TLSKey)
	boolean("REVPD_ACME", &c.Web.ACME)
	str("REVPD_PUBLIC_HOST", &c.Public.Host)
	boolean("REVPD_PUBLIC_DETECT", &c.Public.Detect)
	list("REVPD_PUBLIC_RESOLVERS", &c.Public.Resolvers)
	dur("REVPD_PUBLIC_REFRESH", &c.Public.Refresh)
	integer("REVPD_PUBLIC_RDP_PORT", &c.Public.RDPPort)
	integer("REVPD_PUBLIC_PORTAL_PORT", &c.Public.PortalPort)
	str("REVPD_RELAY_LISTEN", &c.Relay.Listen)
	dur("REVPD_GRANT_TTL", &c.Grant.TTL)
	dur("REVPD_GRANT_REUSE_WINDOW", &c.Grant.ReuseWindow)
	boolean("REVPD_JIT_ENABLED", &c.JIT.Enabled)
	dur("REVPD_JIT_HOLD_TIMEOUT", &c.JIT.HoldTimeout)
	boolean("REVPD_RDGW_ENABLED", &c.RDGW.Enabled)
	boolean("REVPD_REQUIRE_SECOND_FACTOR", &c.Auth.RequireSecondFactor)
	boolean("REVPD_NOTIFY_ENABLED", &c.Notify.Enabled)
	str("REVPD_NOTIFY_URL", &c.Notify.URL)
	str("REVPD_NOTIFY_FORMAT", &c.Notify.Format)
	list("REVPD_NOTIFY_EVENTS", &c.Notify.Events)
	dur("REVPD_NOTIFY_TIMEOUT", &c.Notify.Timeout)
	boolean("REVPD_UPDATE_ENABLED", &c.Update.Enabled)
	boolean("REVPD_UPDATE_AUTO_INSTALL", &c.Update.AutoInstall)
	boolean("REVPD_UPDATE_PRERELEASE", &c.Update.Prerelease)
	boolean("REVPD_UPDATE_ONLY_WHEN_IDLE", &c.Update.OnlyWhenIdle)
	str("REVPD_UPDATE_REPO", &c.Update.Repo)
	dur("REVPD_UPDATE_CHECK_INTERVAL", &c.Update.CheckInterval)

	if v := os.Getenv("REVPD_TRUSTED_PROXIES"); v != "" {
		c.Web.TrustedProxies = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.Web.TrustedProxies = append(c.Web.TrustedProxies, p)
			}
		}
	}
}

// MasterKey returns the at-rest encryption key. It is only ever read from the
// environment — a key sitting in a config file next to the database it
// protects would defeat the point.
func (c Config) MasterKey() string {
	env := c.Auth.MasterKeyEnv
	if env == "" {
		env = "REVPD_MASTER_KEY"
	}
	return strings.TrimSpace(os.Getenv(env))
}

// NotifyConfig is the notification settings in the form the notifier takes.
func (c Config) NotifyConfig() notify.Config {
	return notify.Config{
		Enabled: c.Notify.Enabled,
		URL:     strings.TrimSpace(c.Notify.URL),
		Format:  c.Notify.Format,
		Events:  c.Notify.Events,
		Timeout: c.Notify.Timeout,
	}
}

// Duo returns the push-approval credentials, empty when not configured.
func (c Config) Duo() (host, ikey, skey string) {
	return os.Getenv("REVPD_DUO_API_HOST"), os.Getenv("REVPD_DUO_IKEY"), os.Getenv("REVPD_DUO_SKEY")
}

// PortalIsPublic reports whether the portal accepts connections from outside
// this machine. Used to decide how loudly to warn about a self-signed
// certificate.
func (c Config) PortalIsPublic() bool {
	host, _, err := net.SplitHostPort(c.Web.Listen)
	if err != nil || host == "" {
		return true
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

/* -------------------------------------------------------------- public --- */

// RelayPort is the port Remote Desktop connections arrive on locally.
func (c Config) RelayPort() int { return portOf(c.Relay.Listen, 3389) }

// PortalPort is the port the web interface listens on locally. It is not
// necessarily where it ended up: the fallback moves it when the port is taken,
// and that address is known only at runtime.
func (c Config) PortalPort() int { return portOf(c.Web.Listen, 443) }

// PublicRDPPort is what somebody outside types after the address. Zero in the
// config means the router forwards the port through unchanged, which is both
// the default and the usual case.
func (c Config) PublicRDPPort() int {
	if c.Public.RDPPort > 0 {
		return c.Public.RDPPort
	}
	return c.RelayPort()
}

// PublicPortalPort is the same for the web interface.
func (c Config) PublicPortalPort() int {
	if c.Public.PortalPort > 0 {
		return c.Public.PortalPort
	}
	return c.PortalPort()
}

// PublicHost is the configured public name, falling back to web.hostname.
//
// The fallback matters: an installation that set a real hostname and never
// touched public.host is already correct, and should not have to say the same
// thing twice.
func (c Config) PublicHost() string {
	if h := strings.TrimSpace(c.Public.Host); h != "" {
		return h
	}
	if h := strings.TrimSpace(c.Web.Hostname); h != "" && h != "localhost" {
		return h
	}
	return ""
}

func portOf(listen string, fallback int) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return fallback
	}
	return n
}

// CheckPublicHost rejects anything that is not a bare hostname or address.
//
// A scheme or a port here would silently produce a broken connect string —
// "https://gw.example.com:3389" is not something Remote Desktop can be given —
// so it is refused with the fix rather than accepted and printed.
func CheckPublicHost(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.Contains(v, "://") {
		return fmt.Errorf("%q must be a bare name or address, without https://", v)
	}
	if strings.ContainsAny(v, " \t\r\n/?#@") {
		return fmt.Errorf("%q must be a bare name or address, with no path or spaces", v)
	}
	if net.ParseIP(v) != nil {
		return nil
	}
	if _, _, err := net.SplitHostPort(v); err == nil {
		return fmt.Errorf("%q must not include a port — set public.rdp_port instead", v)
	}
	if !validHostname(v) {
		return fmt.Errorf("%q is not a valid hostname or IP address", v)
	}
	return nil
}

// validHostname checks the shape of a DNS name: labels of letters, digits and
// hyphens, none of them starting or ending with one.
func validHostname(v string) bool {
	if len(v) > 253 {
		return false
	}
	labels := strings.Split(v, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := range len(l) {
			ch := l[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (c Config) Validate() error {
	var problems []string

	if c.DataDir == "" {
		problems = append(problems, "data_dir must be set")
	}
	if c.Web.Listen == "" {
		problems = append(problems, "web.listen must be set")
	}
	if c.Web.Hostname == "" {
		problems = append(problems, "web.hostname must be set (it is also the WebAuthn RP ID)")
	}
	if !c.Web.ACME && (c.Web.TLSCert == "") != (c.Web.TLSKey == "") {
		problems = append(problems, "web.tls_cert and web.tls_key must be set together")
	}

	if _, _, err := net.SplitHostPort(c.Web.Listen); err != nil {
		problems = append(problems, fmt.Sprintf("web.listen %q is not a host:port address", c.Web.Listen))
	}
	if _, _, err := net.SplitHostPort(c.Relay.Listen); err != nil {
		problems = append(problems, fmt.Sprintf("relay.listen %q is not a host:port address", c.Relay.Listen))
	}
	if c.Relay.Listen == "" {
		problems = append(problems, "relay.listen must be set")
	}
	if err := CheckPublicHost(c.Public.Host); err != nil {
		problems = append(problems, "public.host: "+err.Error())
	}
	for _, r := range c.Public.Resolvers {
		if err := netcheck.CheckResolver(r); err != nil {
			problems = append(problems, "public.resolvers: "+err.Error())
		}
	}
	if c.Public.RDPPort < 0 || c.Public.RDPPort > 65535 {
		problems = append(problems, fmt.Sprintf("public.rdp_port %d is not a port number", c.Public.RDPPort))
	}
	if c.Public.PortalPort < 0 || c.Public.PortalPort > 65535 {
		problems = append(problems, fmt.Sprintf("public.portal_port %d is not a port number", c.Public.PortalPort))
	}
	if c.Public.Detect {
		if len(c.Public.Resolvers) == 0 {
			problems = append(problems, "public.detect is on but public.resolvers is empty — there is nobody to ask")
		}
		if c.Public.Refresh < 5*time.Minute {
			// These are somebody else's servers being asked a favour. An
			// address does not change by the minute, and hammering them is
			// how a free endpoint stops being free.
			problems = append(problems, "public.refresh below 5m asks the resolvers far more often than the address can change")
		}
	}
	if c.Grant.TTL <= 0 {
		problems = append(problems, "grant.ttl must be positive")
	}
	if c.Grant.TTL > 30*time.Minute {
		problems = append(problems, "grant.ttl above 30m defeats the point of MFA")
	}
	if c.Grant.IPv4PrefixBits < 16 || c.Grant.IPv4PrefixBits > 32 {
		problems = append(problems, "grant.ipv4_prefix_bits must be between 16 and 32")
	}
	if c.Grant.IPv6PrefixBits < 32 || c.Grant.IPv6PrefixBits > 128 {
		problems = append(problems, "grant.ipv6_prefix_bits must be between 32 and 128")
	}
	if c.JIT.Enabled && c.JIT.HoldTimeout <= 0 {
		problems = append(problems, "jit.hold_timeout must be positive when jit is enabled")
	}
	if c.RDPLogin.Enabled {
		if c.RDPLogin.Timeout <= 0 {
			problems = append(problems, "rdp_login.timeout must be positive")
		}
		if (c.RDPLogin.TLSCert == "") != (c.RDPLogin.TLSKey == "") {
			problems = append(problems, "rdp_login.tls_cert and rdp_login.tls_key must be set together")
		}
	}
	if !c.RDPLogin.Enabled && !c.JIT.Enabled {
		// Not fatal: the portal still works. But it is worth being loud about,
		// because it is almost never what someone meant to configure.
		problems = append(problems, "both rdp_login and jit are disabled — nothing can connect except through the web portal; set rdp_login.enabled: true")
	}
	if c.Auth.MaxFailures < 1 {
		problems = append(problems, "auth.max_failures must be at least 1")
	}
	if c.Auth.TOTPSkew > 2 {
		problems = append(problems, "auth.totp_skew above 2 widens the replay window too far")
	}
	if c.Auth.BackupCodes < 0 || c.Auth.BackupCodes > 50 {
		problems = append(problems, "auth.backup_codes must be between 0 and 50")
	}
	if err := notify.CheckURL(c.Notify.URL); err != nil {
		problems = append(problems, "notify.url: "+err.Error())
	}
	if c.Notify.Format != "" {
		if err := notify.CheckFormat(c.Notify.Format); err != nil {
			problems = append(problems, "notify.format: "+err.Error())
		}
	}
	if err := notify.CheckEvents(c.Notify.Events); err != nil {
		problems = append(problems, "notify.events: "+err.Error())
	}
	if c.Notify.Enabled {
		if strings.TrimSpace(c.Notify.URL) == "" {
			problems = append(problems, "notify.enabled is on but notify.url is empty — there is nowhere to send to")
		}
		if len(c.Notify.Events) == 0 {
			problems = append(problems, "notify.enabled is on but notify.events is empty — nothing would ever be sent")
		}
	}
	if c.Update.Enabled && c.Update.CheckInterval < 15*time.Minute {
		// GitHub allows 60 anonymous API calls an hour per address. Checking
		// more often than this burns the budget for no benefit — releases do
		// not appear by the minute.
		problems = append(problems, "update.check_interval below 15m will exhaust GitHub's rate limit")
	}
	if c.Update.Repo != "" && strings.Count(c.Update.Repo, "/") != 1 {
		problems = append(problems, fmt.Sprintf("update.repo %q must be in owner/name form", c.Update.Repo))
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

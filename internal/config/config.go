// Package config loads and validates revpd.yaml.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string `yaml:"data_dir"`

	Web      Web      `yaml:"web"`
	Relay    Relay    `yaml:"relay"`
	Grant    Grant    `yaml:"grant"`
	RDPLogin RDPLogin `yaml:"rdp_login"`
	JIT      JIT      `yaml:"jit"`
	WoL      WoL      `yaml:"wol"`
	Auth     Auth     `yaml:"auth"`
	RDGW     RDGW     `yaml:"rdgw"`
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

	str("REVPD_DATA_DIR", &c.DataDir)
	str("REVPD_WEB_LISTEN", &c.Web.Listen)
	str("REVPD_WEB_HOSTNAME", &c.Web.Hostname)
	str("REVPD_TLS_CERT", &c.Web.TLSCert)
	str("REVPD_TLS_KEY", &c.Web.TLSKey)
	boolean("REVPD_ACME", &c.Web.ACME)
	str("REVPD_RELAY_LISTEN", &c.Relay.Listen)
	dur("REVPD_GRANT_TTL", &c.Grant.TTL)
	dur("REVPD_GRANT_REUSE_WINDOW", &c.Grant.ReuseWindow)
	boolean("REVPD_JIT_ENABLED", &c.JIT.Enabled)
	dur("REVPD_JIT_HOLD_TIMEOUT", &c.JIT.HoldTimeout)
	boolean("REVPD_RDGW_ENABLED", &c.RDGW.Enabled)
	boolean("REVPD_REQUIRE_SECOND_FACTOR", &c.Auth.RequireSecondFactor)
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

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
	WoL   WoL   `yaml:"wol"`
	Auth  Auth  `yaml:"auth"`
	RDGW  RDGW  `yaml:"rdgw"`
}

type Web struct {
	// Listen is the portal. Together with relay.listen these are the only two
	// ports that face the internet; nothing else is opened.
	//
	// The portal always speaks TLS. Leaving tls_cert empty means a self-signed
	// certificate is generated rather than falling back to plain HTTP, so a
	// session cookie is never handed out in the clear.
	Listen string `yaml:"listen"`

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

	MaxFailures  int           `yaml:"max_failures"`
	LockoutBase  time.Duration `yaml:"lockout_base"`
	LockoutMax   time.Duration `yaml:"lockout_max"`
	TOTPSkew     uint          `yaml:"totp_skew"`
	BackupCodes  int           `yaml:"backup_codes"`
	MasterKeyEnv string        `yaml:"master_key_env"`
}

type RDGW struct {
	Enabled  bool          `yaml:"enabled"`
	Listen   string        `yaml:"listen"`
	TokenTTL time.Duration `yaml:"token_ttl"`
}

// Defaults returns a config that is safe to run as-is apart from hostname and TLS.
func Defaults() Config {
	return Config{
		DataDir: "/var/lib/revpd",
		Web: Web{
			Listen:   ":8443",
			Hostname: "localhost",
			ACME:     false,
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
			SessionTTL:   12 * time.Hour,
			SessionIdle:  30 * time.Minute,
			MaxFailures:  5,
			LockoutBase:  30 * time.Second,
			LockoutMax:   1 * time.Hour,
			TOTPSkew:     1,
			BackupCodes:  10,
			MasterKeyEnv: "REVPD_MASTER_KEY",
		},
		RDGW: RDGW{
			Enabled:  false,
			Listen:   ":443",
			TokenTTL: 5 * time.Minute,
		},
	}
}

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

	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

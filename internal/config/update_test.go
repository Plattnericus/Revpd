package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The example is what people copy and what install.sh documents. Load rejects
// unknown keys, so a block documented there but never added here would only
// surface as a refused config on somebody's server.
func TestExampleConfigStillLoads(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "revpd.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skip("example config not present")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if !cfg.Update.Enabled {
		t.Error("the example turns update checking off")
	}
	if cfg.Update.AutoInstall {
		t.Error("the example installs updates unattended — that has to be opt-in")
	}
	if !cfg.Update.OnlyWhenIdle {
		t.Error("the example would cut live sessions to install an update")
	}
}

// Checking is on out of the box; installing is not. An update restarts the
// service, so nobody should get that by accident.
func TestUpdateDefaults(t *testing.T) {
	d := Defaults().Update

	if !d.Enabled {
		t.Error("update checking is off by default")
	}
	if d.AutoInstall {
		t.Error("automatic installation is on by default")
	}
	if !d.OnlyWhenIdle {
		t.Error("automatic installation would not wait for the gateway to be idle")
	}
	if d.Prerelease {
		t.Error("pre-releases are accepted by default")
	}
	if d.CheckInterval < 15*time.Minute {
		t.Errorf("check_interval default %s would exhaust GitHub's rate limit", d.CheckInterval)
	}
}

func TestUpdateValidation(t *testing.T) {
	cases := []struct {
		name  string
		set   func(*Config)
		wants string
	}{
		{
			// 60 anonymous API calls an hour, per address.
			name:  "polling too fast",
			set:   func(c *Config) { c.Update.CheckInterval = time.Minute },
			wants: "rate limit",
		},
		{
			name:  "repo that is not owner/name",
			set:   func(c *Config) { c.Update.Repo = "revpd" },
			wants: "owner/name",
		},
		{
			name:  "repo with too many parts",
			set:   func(c *Config) { c.Update.Repo = "github.com/o/r" },
			wants: "owner/name",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Web.Hostname = "gw.example.com"
			c.set(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("error %q does not mention %q", err, c.wants)
			}
		})
	}
}

// A slow check interval must not be rejected just because checking is off.
func TestUpdateIntervalIgnoredWhenCheckingIsOff(t *testing.T) {
	cfg := Defaults()
	cfg.Web.Hostname = "gw.example.com"
	cfg.Update.Enabled = false
	cfg.Update.CheckInterval = time.Second

	if err := cfg.Validate(); err != nil {
		t.Fatalf("rejected a setting that has no effect: %v", err)
	}
}

func TestUpdateEnvOverrides(t *testing.T) {
	t.Setenv("REVPD_UPDATE_AUTO_INSTALL", "true")
	t.Setenv("REVPD_UPDATE_REPO", "someone/revpd")
	t.Setenv("REVPD_UPDATE_CHECK_INTERVAL", "2h")

	cfg := Defaults()
	cfg.applyEnv()

	if !cfg.Update.AutoInstall {
		t.Error("REVPD_UPDATE_AUTO_INSTALL was ignored")
	}
	if cfg.Update.Repo != "someone/revpd" {
		t.Errorf("repo = %q", cfg.Update.Repo)
	}
	if cfg.Update.CheckInterval != 2*time.Hour {
		t.Errorf("check_interval = %s", cfg.Update.CheckInterval)
	}
}

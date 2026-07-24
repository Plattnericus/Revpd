package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The deployment files ship to users, so a typo in them is a broken install
// rather than a broken build. Parse them the same way the runtime would.
func repoFile(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func TestComposeFileIsValid(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Image       string   `yaml:"image"`
			NetworkMode string   `yaml:"network_mode"`
			CapAdd      []string `yaml:"cap_add"`
			SecurityOpt []string `yaml:"security_opt"`
			ReadOnly    bool     `yaml:"read_only"`
			Volumes     []string `yaml:"volumes"`
			EnvFile     []string `yaml:"env_file"`
		} `yaml:"services"`
		Volumes map[string]any `yaml:"volumes"`
	}

	if err := yaml.Unmarshal(repoFile(t, "docker-compose.yml"), &compose); err != nil {
		t.Fatalf("docker-compose.yml is not valid yaml: %v", err)
	}

	svc, ok := compose.Services["revpd"]
	if !ok {
		t.Fatal("docker-compose.yml has no revpd service")
	}

	// Wake-on-LAN is layer 2. From a bridged container the magic packet would
	// never reach the LAN, so this is a requirement rather than a preference.
	if svc.NetworkMode != "host" {
		t.Fatalf("network_mode = %q, want host or Wake-on-LAN cannot work", svc.NetworkMode)
	}

	// Binding 3389 is the only privilege the process needs.
	if len(svc.CapAdd) != 1 || svc.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Fatalf("cap_add = %v, want exactly NET_BIND_SERVICE", svc.CapAdd)
	}
	if !contains(svc.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("security_opt = %v, want no-new-privileges", svc.SecurityOpt)
	}
	if !svc.ReadOnly {
		t.Fatal("the container filesystem is writable; it should be read_only")
	}

	// The database has to survive a recreate, so it must be on a volume.
	if !hasSuffixIn(svc.Volumes, ":/var/lib/revpd") {
		t.Fatalf("volumes = %v, want the data directory persisted", svc.Volumes)
	}
	if len(compose.Volumes) == 0 {
		t.Fatal("no named volume is declared")
	}
	if len(svc.EnvFile) == 0 {
		t.Fatal("no env_file; the master key would be missing")
	}
}

// The Dockerfile has to produce a static binary for the distroless base, and
// the frontend has to be built before the Go build embeds it.
func TestDockerfileBuildsStatically(t *testing.T) {
	text := string(repoFile(t, "Dockerfile"))

	for _, want := range []string{
		"CGO_ENABLED=0",              // static, no libc on distroless
		"AS web",                     // frontend stage
		"AS build",                   // binary stage
		"distroless",                 // runtime base
		"USER nonroot",               // not root
		"--from=web /src/internal/web/dist", // frontend reaches the embed
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}

	// The copy of the built frontend has to come before the go build, or the
	// embed directive finds nothing.
	copyAt := strings.Index(text, "--from=web")
	buildAt := strings.Index(text, "go build")
	if copyAt < 0 || buildAt < 0 || copyAt > buildAt {
		t.Fatal("the frontend is copied after the go build; embed would find no files")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func hasSuffixIn(hay []string, suffix string) bool {
	for _, h := range hay {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

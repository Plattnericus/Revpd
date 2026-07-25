package main

import (
	"os"
	"strings"
	"testing"
)

// The installer carries its own copy of the unit because it runs from curl,
// with no repository around it. The two drifted apart once already — a
// hardening directive that only exists in deploy/revpd.service protects
// nobody, since install.sh is what actually lands on a machine.
func TestInstallerUnitMatchesTheShippedOne(t *testing.T) {
	shipped, err := os.ReadFile("../../deploy/revpd.service")
	if err != nil {
		t.Fatalf("read the unit: %v", err)
	}
	installer, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatalf("read the installer: %v", err)
	}

	embedded := between(string(installer), "cat > \"$SERVICE\" <<'EOF'\n", "\nEOF\n")
	if embedded == "" {
		t.Fatal("no unit file found in install.sh — did the heredoc change?")
	}

	want := directives(string(shipped))
	got := directives(embedded)

	for key, value := range want {
		if got[key] != value {
			t.Errorf("install.sh has %s=%q, deploy/revpd.service has %q", key, got[key], value)
		}
	}
	for key, value := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("install.sh sets %s=%q, which the shipped unit does not have", key, value)
		}
	}
}

// directives reduces a unit to what it actually does, so comments and blank
// lines are free to differ.
func directives(unit string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// A few directives are legitimately repeated.
		if existing, seen := out[key]; seen {
			out[key] = existing + "\x00" + value
			continue
		}
		out[key] = value
	}
	return out
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

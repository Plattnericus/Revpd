package main

import (
	"strings"
	"testing"
)

/*
   The uninstaller deletes directories recursively as root. The plan it works
   from is a pure function precisely so it can be tested without deleting
   anything, and so the guard against a catastrophic path is provable.
*/

func TestUninstallPlanCoversEverything(t *testing.T) {
	steps, err := uninstallPlan("/var/lib/revpd", false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	want := []string{
		"/usr/local/bin/revpd",             // the program
		"/etc/revpd",                       // master key and config
		"/var/lib/revpd",                   // database
		"/etc/systemd/system/revpd.service", // the unit
	}
	for _, w := range want {
		if !planTouchesPath(steps, w) {
			t.Errorf("the plan never removes %s", w)
		}
	}

	for _, cmd := range []string{"systemctl", "userdel"} {
		if !planRunsCommand(steps, cmd) {
			t.Errorf("the plan never runs %s", cmd)
		}
	}
}

// The program must go last, or the steps after it would have nothing to run.
func TestUninstallRemovesTheBinaryLast(t *testing.T) {
	steps, err := uninstallPlan("/var/lib/revpd", false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	last := steps[len(steps)-1]
	if last.Path != installBinPath {
		t.Fatalf("the last step is %q, want the binary", firstNonEmpty(last.Path, strings.Join(last.Command, " ")))
	}
}

// The service has to stop before its files go, or systemd is left holding a
// unit whose binary vanished.
func TestUninstallStopsBeforeDeleting(t *testing.T) {
	steps, _ := uninstallPlan("/var/lib/revpd", false)

	stopAt, unitAt := -1, -1
	for i, s := range steps {
		if len(s.Command) > 1 && s.Command[1] == "stop" {
			stopAt = i
		}
		if s.Path == installService {
			unitAt = i
		}
	}

	if stopAt < 0 || unitAt < 0 {
		t.Fatal("the plan is missing the stop or the unit removal")
	}
	if stopAt > unitAt {
		t.Fatal("the unit file is deleted before the service is stopped")
	}
}

// --keep-data has to mean exactly that.
func TestKeepDataSpares(t *testing.T) {
	steps, err := uninstallPlan("/var/lib/revpd", true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	for _, spared := range []string{"/var/lib/revpd", "/etc/revpd"} {
		if planTouchesPath(steps, spared) {
			t.Errorf("--keep-data still removes %s", spared)
		}
	}

	// But the program and the service must still go.
	if !planTouchesPath(steps, installBinPath) {
		t.Error("--keep-data left the program installed")
	}
	if !planTouchesPath(steps, installService) {
		t.Error("--keep-data left the service behind")
	}
}

// A custom data_dir from the config must be the one that gets removed.
func TestPlanUsesTheConfiguredDataDir(t *testing.T) {
	steps, err := uninstallPlan("/srv/revpd-data", false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if !planTouchesPath(steps, "/srv/revpd-data") {
		t.Fatal("the configured data directory is not in the plan")
	}
	if planTouchesPath(steps, "/var/lib/revpd") {
		t.Fatal("the default data directory is removed as well as the configured one")
	}
}

// An empty data_dir must fall back, never become a delete of "".
func TestEmptyDataDirFallsBack(t *testing.T) {
	steps, err := uninstallPlan("", false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !planTouchesPath(steps, installDataDir) {
		t.Fatal("an empty data dir did not fall back to the default")
	}
}

// The guard that matters most: nothing may ever resolve to the root of the
// filesystem, a top-level directory, or a relative path.
func TestPlanRefusesDangerousPaths(t *testing.T) {
	for _, dangerous := range []string{"/", "//", "/.", "relative/path", ".", "..", "/etc", "/var", "/usr"} {
		steps, err := uninstallPlan(dangerous, false)

		if err != nil {
			continue // refused outright, which is the point
		}
		for _, s := range steps {
			if s.Path != "" && !safeToRemove(s.Path) {
				t.Fatalf("data dir %q produced a step that would remove %q", dangerous, s.Path)
			}
		}
	}
}

// safeToRemove is the last line of defence, so test it directly rather than
// only through the plan.
func TestSafeToRemove(t *testing.T) {
	safe := []string{
		"/usr/local/bin/revpd",
		"/etc/revpd",
		"/var/lib/revpd",
		"/etc/systemd/system/revpd.service",
		"/srv/revpd-data",
	}
	for _, p := range safe {
		if !safeToRemove(p) {
			t.Errorf("safeToRemove(%q) = false, want true", p)
		}
	}

	dangerous := []string{
		"", "/", "//", "/.", ".", "..",
		"/etc", "/var", "/usr", "/home", // whole top-level directories
		"relative/path", "revpd",
		"/var/lib/../../etc", // climbing out
	}
	for _, p := range dangerous {
		if safeToRemove(p) {
			t.Errorf("safeToRemove(%q) = true — this would be a catastrophe", p)
		}
	}
}

// Every step must do exactly one thing, so the executor cannot misread it.
func TestEveryStepIsWellFormed(t *testing.T) {
	steps, _ := uninstallPlan("/var/lib/revpd", false)

	for i, s := range steps {
		hasPath := s.Path != ""
		hasCmd := len(s.Command) > 0

		if hasPath == hasCmd {
			t.Errorf("step %d has both a path and a command, or neither", i)
		}
		if s.Description == "" {
			t.Errorf("step %d has nothing to show the operator", i)
		}
	}
}

/* ---------------------------------------------------------------- args --- */

func TestSplitNameSeparatesFlags(t *testing.T) {
	cases := []struct {
		args  []string
		name  string
		flags int
	}{
		{[]string{"felix"}, "felix", 0},
		{[]string{"felix", "--admin"}, "felix", 1},
		{[]string{"--admin", "felix"}, "felix", 1},
		{[]string{"--admin", "--yes", "felix"}, "felix", 2},
		{nil, "", 0},
		{[]string{"--admin"}, "", 1},
	}

	for _, tc := range cases {
		name, flags := splitName(tc.args)
		if name != tc.name || len(flags) != tc.flags {
			t.Errorf("splitName(%v) = %q, %d flags; want %q, %d",
				tc.args, name, len(flags), tc.name, tc.flags)
		}
	}
}

func TestValueOfReadsBothForms(t *testing.T) {
	if got := valueOf([]string{"--for", "felix"}, "--for"); got != "felix" {
		t.Errorf("--for felix gave %q", got)
	}
	if got := valueOf([]string{"--for=felix"}, "--for"); got != "felix" {
		t.Errorf("--for=felix gave %q", got)
	}
	if got := valueOf([]string{"--for"}, "--for"); got != "" {
		t.Errorf("a dangling --for gave %q", got)
	}
}

func TestExpandPathHandlesTilde(t *testing.T) {
	got := expandPath("~/backups")
	if strings.HasPrefix(got, "~") {
		t.Fatalf("~ was not expanded: %q", got)
	}

	// Anything else must be left exactly as typed.
	for _, p := range []string{"/etc/revpd", "relative", ""} {
		if expandPath(p) != p {
			t.Errorf("expandPath(%q) changed it to %q", p, expandPath(p))
		}
	}
}

func TestCommonPrefix(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"backup-1", "backup-2"}, "backup-"},
		{[]string{"same", "same"}, "same"},
		{[]string{"a", "b"}, ""},
		{[]string{"only"}, "only"},
		{nil, ""},
	}

	for _, tc := range cases {
		if got := commonPrefix(tc.in); got != tc.want {
			t.Errorf("commonPrefix(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMenuIndexParsing(t *testing.T) {
	if _, ok := index("3", 8); !ok {
		t.Error("3 was not accepted out of 8")
	}
	for _, bad := range []string{"0", "9", "-1", "abc", "", "1x"} {
		if _, ok := index(bad, 8); ok {
			t.Errorf("%q was accepted as a menu choice", bad)
		}
	}
}

/* ---------------------------------------------------------------- util --- */

func planTouchesPath(steps []removalStep, path string) bool {
	for _, s := range steps {
		if s.Path == path {
			return true
		}
	}
	return false
}

func planRunsCommand(steps []removalStep, cmd string) bool {
	for _, s := range steps {
		if len(s.Command) > 0 && s.Command[0] == cmd {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

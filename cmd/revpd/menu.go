package main

import (
	"fmt"
	"os"
	"strings"
)

/*
   The menu shown when someone types just `revpd` in a terminal.

   Modelled on sconfig: a numbered list, one thing per line, no flags to
   remember. Every entry calls exactly the same function as the scriptable
   command, so the two can never drift apart.
*/

type menuItem struct {
	label  string
	hint   string
	action func() error
}

func runMenu() error {
	for {
		clearish()
		header()

		items := mainItems()
		render(items)

		choice := strings.TrimSpace(prompt("Select"))
		switch choice {
		case "0", "q", "quit", "exit":
			sayf("\n")
			return nil
		case "":
			continue
		}

		idx, ok := index(choice, len(items))
		if !ok {
			warnf("pick a number between 1 and %d", len(items))
			pause()
			continue
		}

		if err := items[idx].action(); err != nil {
			sayf("\n  %serror:%s %v\n", rd, reset, err)
		}
		pause()
	}
}

func header() {
	sayf("\n  %sRevpd%s %s%s%s\n", bold, reset, dim, version, reset)
	sayf("  %sMFA gateway for RDP with Wake-on-LAN%s\n", dim, reset)

	// The status line is the reason to open this at all: is it running?
	state := serviceState()
	colour := green
	if !strings.HasPrefix(state, "running") {
		colour = yellow
	}
	sayf("\n  Service: %s%s%s\n", colour, state, reset)
}

func mainItems() []menuItem {
	return []menuItem{
		// First, because it is what someone with a problem needs.
		{"Check everything", "find problems and say how to fix them", cmdDoctor},
		{"Users", "add, remove, reset a second factor", menuUsers},
		{"Machines", "the computers people connect to", menuTargets},
		{"Who can reach what", "grant and revoke access", menuAccess},
		{"Service", "start, stop, restart", menuService},
		{"Logs and history", "what the gateway is doing", menuHistory},
		{"Backup", "save or restore everything", menuBackup},
		{"Settings", "what it is running with", func() error { return cmdConfig(nil) }},
		{"Uninstall", "remove Revpd from this machine", func() error { return cmdUninstall(nil) }},
	}
}

func menuAccess() error {
	clearish()
	sayf("\n  %sWho can reach what%s\n", bold, reset)

	if err := accessList(); err != nil {
		sayf("\n  %serror:%s %v\n", rd, reset, err)
		return nil
	}

	items := []menuItem{
		{"Give someone access", "", func() error { return askTwo(accessGrant, "User", "Machine") }},
		{"Take access away", "", func() error { return askTwo(accessRevoke, "User", "Machine") }},
	}
	render(items)

	choice := strings.TrimSpace(prompt("Select"))
	if choice == "0" || choice == "" {
		return nil
	}

	idx, ok := index(choice, len(items))
	if !ok {
		return nil
	}
	return items[idx].action()
}

func menuHistory() error {
	items := []menuItem{
		{"Recent activity", "logins, wake-ups, connections", func() error { return cmdAuditList(nil) }},
		{"Live service log", "follow what it is doing now", func() error { return cmdLogs([]string{"-f"}) }},
		{"Who is connected", "", func() error { return cmdSessions(nil) }},
		{"Verify the audit trail", "prove nobody edited it", func() error { return cmdAudit([]string{"verify"}) }},
	}

	clearish()
	sayf("\n  %sLogs and history%s\n", bold, reset)
	render(items)

	choice := strings.TrimSpace(prompt("Select"))
	if choice == "0" || choice == "" {
		return nil
	}

	idx, ok := index(choice, len(items))
	if !ok {
		return nil
	}
	return items[idx].action()
}

func accessGrant(args []string) error  { return accessChange(args, true) }
func accessRevoke(args []string) error { return accessChange(args, false) }

// askTwo prompts for two values, for the commands that pair a user with a
// machine.
func askTwo(fn func([]string) error, first, second string) error {
	a := ask(first+":", "")
	if a == "" {
		return nil
	}
	b := ask(second+":", "")
	if b == "" {
		return nil
	}
	return fn([]string{a, b})
}

/* ------------------------------------------------------------ submenus --- */

func menuUsers() error {
	for {
		clearish()
		sayf("\n  %sUsers%s\n", bold, reset)

		if err := userList(); err != nil {
			sayf("\n  %serror:%s %v\n", rd, reset, err)
			return nil
		}

		items := []menuItem{
			{"Add a user", "", func() error { return userAdd(askArgs("Username", "--admin? add --admin")) }},
			{"Remove a user", "", func() error { return userAdd0(userRemove, "Username") }},
			{"Reset someone's second factor", "new QR code and backup codes", func() error { return userAdd0(userReset, "Username") }},
			{"Lock a user out", "", func() error {
				return userAdd0(func(a []string) error { return userSetStatus(a, "locked") }, "Username")
			}},
			{"Let a user back in", "", func() error {
				return userAdd0(func(a []string) error { return userSetStatus(a, "active") }, "Username")
			}},
		}
		render(items)

		choice := strings.TrimSpace(prompt("Select"))
		if choice == "0" || choice == "" {
			return nil
		}

		idx, ok := index(choice, len(items))
		if !ok {
			continue
		}
		if err := items[idx].action(); err != nil {
			sayf("\n  %serror:%s %v\n", rd, reset, err)
		}
		pause()
	}
}

func menuTargets() error {
	for {
		clearish()
		sayf("\n  %sMachines%s\n", bold, reset)

		if err := targetList(); err != nil {
			sayf("\n  %serror:%s %v\n", rd, reset, err)
			return nil
		}

		items := []menuItem{
			{"Add a machine", "", menuAddTarget},
			{"Remove a machine", "", func() error { return userAdd0(targetRemove, "Name") }},
		}
		render(items)

		choice := strings.TrimSpace(prompt("Select"))
		if choice == "0" || choice == "" {
			return nil
		}

		idx, ok := index(choice, len(items))
		if !ok {
			continue
		}
		if err := items[idx].action(); err != nil {
			sayf("\n  %serror:%s %v\n", rd, reset, err)
		}
		pause()
	}
}

// menuAddTarget asks for the three things a machine needs, one at a time.
func menuAddTarget() error {
	sayf("\n")
	name := ask("Name (e.g. Office PC):", "")
	if name == "" {
		return nil
	}

	ip := ask("IP address:", "")
	if ip == "" {
		return nil
	}

	sayf("  %sThe MAC address is what wakes it. Any format works.%s\n", dim, reset)
	mac := ask("MAC address:", "")
	if mac == "" {
		return nil
	}

	who := ask("Give access to which user? (blank for nobody yet):", "")

	args := []string{name, ip, mac}
	if who != "" {
		args = append(args, "--for", who)
	}
	return targetAdd(args)
}

func menuService() error {
	items := []menuItem{
		{"Start", "", func() error { return cmdService([]string{"start"}) }},
		{"Stop", "", func() error { return cmdService([]string{"stop"}) }},
		{"Restart", "", func() error { return cmdService([]string{"restart"}) }},
		{"Detailed status", "", func() error { return cmdService([]string{"status"}) }},
	}

	clearish()
	sayf("\n  %sService%s — currently %s\n", bold, reset, serviceState())
	render(items)

	choice := strings.TrimSpace(prompt("Select"))
	if choice == "0" || choice == "" {
		return nil
	}

	idx, ok := index(choice, len(items))
	if !ok {
		return nil
	}
	return items[idx].action()
}

func menuBackup() error {
	items := []menuItem{
		{"Save a backup", "database, master key and settings in one file", func() error { return cmdBackup(nil) }},
		{"Restore from a backup", "replaces everything on this machine", func() error { return cmdRestore(nil) }},
	}

	clearish()
	sayf("\n  %sBackup%s\n", bold, reset)
	sayf("\n  %sOne encrypted file holds everything. Copy it to another machine\n"+
		"  and restore it there, or keep it somewhere safe.%s\n", dim, reset)
	render(items)

	choice := strings.TrimSpace(prompt("Select"))
	if choice == "0" || choice == "" {
		return nil
	}

	idx, ok := index(choice, len(items))
	if !ok {
		return nil
	}
	return items[idx].action()
}

/* ------------------------------------------------------------- plumbing --- */

func render(items []menuItem) {
	sayf("\n")
	for i, it := range items {
		if it.hint != "" {
			sayf("   %s%d%s  %-32s %s%s%s\n", bold, i+1, reset, it.label, dim, it.hint, reset)
			continue
		}
		sayf("   %s%d%s  %s\n", bold, i+1, reset, it.label)
	}
	sayf("\n   %s0%s  Back\n", bold, reset)
}

func prompt(label string) string {
	sayf("\n  %s: ", label)

	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		// Ctrl-D. Treat it as "back", which is what it means everywhere else.
		return "0"
	}
	return cleanPipedLine(line)
}

func index(choice string, max int) (int, bool) {
	n := 0
	for _, r := range choice {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	if n < 1 || n > max {
		return 0, false
	}
	return n - 1, true
}

func pause() {
	sayf("\n  %sPress Enter to continue%s", dim, reset)
	stdin.ReadString('\n')
}

// clearish moves the previous screen out of the way without wiping scrollback,
// so someone can still scroll up to read what happened.
func clearish() {
	if bold == "" {
		// No terminal styling means no cursor control either.
		sayf("\n\n")
		return
	}
	fmt.Print("\033[H\033[2J")
}

// askArgs turns a menu prompt into the argument list a command expects, so the
// menu and the command line share one implementation.
func askArgs(label, hint string) []string {
	if hint != "" {
		sayf("  %s%s%s\n", dim, hint, reset)
	}
	answer := ask(label+":", "")
	if answer == "" {
		return nil
	}
	return strings.Fields(answer)
}

// userAdd0 prompts for one name and hands it to a command.
func userAdd0(fn func([]string) error, label string) error {
	name := ask(label+":", "")
	if name == "" {
		return nil
	}
	return fn([]string{name})
}

var _ = os.Exit

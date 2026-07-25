package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"
)

/*
   Terminal presentation and prompts.

   Everything here degrades: without a terminal there is no colour and no
   prompting, so piping into the binary prints plain text and never blocks
   waiting for an answer that will not come.
*/

var (
	bold, dim, reset  string
	green, yellow, rd string
	blue              string
)

func init() {
	if !isTTY(os.Stdout) || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return
	}
	bold, dim, reset = "\033[1m", "\033[2m", "\033[0m"
	green, yellow, rd, blue = "\033[32m", "\033[33m", "\033[31m", "\033[34m"
}

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// isInteractive reports whether we can hold a conversation with a person.
// Both directions matter: a prompt is pointless if the answer comes from a
// pipe, and equally pointless if nobody can see the question.
func isInteractive() bool { return isTTY(os.Stdin) && isTTY(os.Stdout) }

func sayf(format string, args ...any)  { fmt.Printf(format, args...) }
func step(s string)                    { fmt.Printf("\n%s==>%s %s%s%s\n", blue, reset, bold, s, reset) }
func okf(format string, args ...any)   { fmt.Printf("  %s✓%s %s\n", green, reset, fmt.Sprintf(format, args...)) }
func warnf(format string, args ...any) { fmt.Printf("  %s!%s %s\n", yellow, reset, fmt.Sprintf(format, args...)) }

/* -------------------------------------------------------------- prompts --- */

// ask reads a line, offering a default that Enter accepts.
func ask(prompt, def string) string {
	if !isInteractive() {
		return def
	}

	if def != "" {
		fmt.Printf("  %s %s[%s]%s ", prompt, dim, def, reset)
	} else {
		fmt.Printf("  %s ", prompt)
	}

	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return def
	}

	answer := strings.TrimSpace(cleanPipedLine(line))
	if answer == "" {
		return def
	}
	return answer
}

// confirm asks a yes/no question. Anything but an explicit yes is a no.
func confirm(question string) bool {
	if !isInteractive() {
		return false
	}

	answer := strings.ToLower(ask(question+" [y/N]", ""))
	return answer == "y" || answer == "yes"
}

// confirmTyped demands an exact word, for things that cannot be undone.
// A reflexive "y" should not be enough to delete everything.
func confirmTyped(prompt, want string) bool {
	if !isInteractive() {
		return false
	}

	fmt.Printf("  %s", prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(cleanPipedLine(line)) == want
}

// askNewPassword takes a password twice and checks it is long enough.
func askNewPassword() (string, error) {
	if !isInteractive() {
		// Scripted: one line on stdin, the same shape useradd -password-stdin
		// already accepts.
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw := cleanPipedLine(line)
		if len(pw) < 12 {
			return "", fmt.Errorf("password must be at least 12 characters")
		}
		return pw, nil
	}

	for {
		pw, err := readPassword("  Password (at least 12 characters): ")
		if err != nil {
			return "", err
		}
		if len(pw) < 12 {
			warnf("too short — %d characters, needs 12", len(pw))
			continue
		}

		again, err := readPassword("  Repeat: ")
		if err != nil {
			return "", err
		}
		if pw != again {
			warnf("they do not match, try again")
			continue
		}
		return pw, nil
	}
}

// askNewPassphrase is the same for a backup, with wording that explains why
// losing it matters.
func askNewPassphrase() (string, error) {
	if !isInteractive() {
		if pw := os.Getenv("REVPD_BACKUP_PASSPHRASE"); pw != "" {
			return pw, nil
		}
		return "", fmt.Errorf("set REVPD_BACKUP_PASSPHRASE to make a backup without a terminal")
	}

	sayf("\n  The backup holds the key to every enrolled second factor, so it is\n" +
		"  encrypted. There is no way to recover this passphrase.\n\n")

	for {
		pw, err := readPassword("  Passphrase: ")
		if err != nil {
			return "", err
		}
		if len(pw) < 8 {
			warnf("too short — use at least 8 characters")
			continue
		}

		again, err := readPassword("  Repeat: ")
		if err != nil {
			return "", err
		}
		if pw != again {
			warnf("they do not match, try again")
			continue
		}
		return pw, nil
	}
}

/* ----------------------------------------------------------- path input --- */

// askPath reads a filesystem path with Tab completion.
//
// Falls back to a plain line read when the terminal cannot be put into raw
// mode, so this never becomes the reason a command fails.
func askPath(prompt, def string) string {
	if !isInteractive() {
		return def
	}

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return ask(prompt+":", def)
	}
	defer term.Restore(fd, oldState)

	t := term.NewTerminal(os.Stdout, "")
	t.AutoCompleteCallback = completePath

	// The prompt has to be written through the terminal, or raw mode leaves
	// the cursor in the wrong place.
	t.SetPrompt(fmt.Sprintf("  %s %s[Tab completes]%s\n  > ", prompt, dim, reset))

	if def != "" {
		fmt.Fprintf(t, "  %sdefault: %s%s\r\n", dim, def, reset)
	}

	line, err := t.ReadLine()
	if err != nil {
		return def
	}

	answer := strings.TrimSpace(line)
	if answer == "" {
		return def
	}
	return answer
}

// completePath fills in directory and file names on Tab.
//
// One Tab completes as far as the entries agree; a second Tab with nothing to
// add lists them. That is what people expect from a shell.
func completePath(line string, pos int, key rune) (string, int, bool) {
	if key != '\t' {
		return "", 0, false
	}

	prefix := expandPath(line[:pos])

	dir := filepath.Dir(prefix)
	base := filepath.Base(prefix)
	if strings.HasSuffix(prefix, string(os.PathSeparator)) || prefix == "" {
		dir = strings.TrimSuffix(prefix, string(os.PathSeparator))
		if dir == "" {
			dir = "."
		}
		base = ""
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, false
	}

	var matches []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		// Hidden files only when they were asked for by name.
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}
		if e.IsDir() {
			name += string(os.PathSeparator)
		}
		matches = append(matches, name)
	}

	if len(matches) == 0 {
		return "", 0, false
	}
	sort.Strings(matches)

	completed := commonPrefix(matches)
	full := filepath.Join(dir, completed)
	if strings.HasSuffix(completed, string(os.PathSeparator)) {
		full += string(os.PathSeparator)
	}

	return full, len(full), true
}

func commonPrefix(items []string) string {
	if len(items) == 0 {
		return ""
	}
	prefix := items[0]
	for _, s := range items[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// expandPath turns ~ into the home directory, which people type constantly.
func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~"+string(os.PathSeparator)) || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), string(os.PathSeparator)))
		}
	}
	return p
}

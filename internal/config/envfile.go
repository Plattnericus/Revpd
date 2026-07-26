package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

/*
	Reading the secrets file the way the service does.

	The master key lives in .env next to revpd.yaml, and systemd hands it to
	the service through EnvironmentFile=. Nothing hands it to the command line,
	which is why every command that opens the database used to fail with

	    REVPD_MASTER_KEY is not set — generate one with `revpd genkey`

	even when the key was sitting right there, and even under sudo. The advice
	was wrong as well as unhelpful: generating a second key would have made the
	existing database unreadable.

	So the same file is read here. Not to introduce a second source of truth —
	it is the same file, parsed the same way — but so that `sudo revpd …` and
	the service agree about what the key is.
*/

// LoadEnvFile reads KEY=VALUE lines into the environment.
//
// A variable already set wins: someone who exported REVPD_MASTER_KEY meant it,
// and a file quietly overriding an explicit choice is the kind of surprise
// that costs an afternoon.
//
// A missing file is not an error. Docker passes the key in the environment and
// has no .env at all.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseEnvLine(scanner.Text())
		if !ok {
			continue
		}
		if _, already := os.LookupEnv(key); already {
			continue
		}
		os.Setenv(key, value)
	}
	return scanner.Err()
}

// parseEnvLine reads one line of an EnvironmentFile.
//
// Deliberately narrow: systemd's own parser accepts more, but this file is
// written by the installer and holds a handful of values. Anything it does not
// recognise is skipped rather than guessed at.
func parseEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}

	key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
	if key == "" {
		return "", "", false
	}

	value = strings.TrimSpace(value)

	// Quotes are stripped, because people add them and systemd accepts them.
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

// EnvFilePath is where the secrets sit for a given configuration file: beside
// it, which is where the installer puts them and where the unit file looks.
func EnvFilePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), ".env")
}

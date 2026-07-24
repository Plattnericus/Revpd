package main

import (
	"os"

	"golang.org/x/term"
)

// readNoEcho reads a line from the terminal with echo turned off.
// Returns an error when stdin is not a terminal, e.g. under a pipe.
func readNoEcho() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", os.ErrInvalid
	}

	b, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

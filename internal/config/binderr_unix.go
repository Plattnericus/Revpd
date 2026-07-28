//go:build !windows

package config

import "syscall"

var (
	errsInUse    = []error{syscall.EADDRINUSE}
	errsDenied   = []error{syscall.EACCES, syscall.EPERM}
	errsNoSuchIP = []error{syscall.EADDRNOTAVAIL}
)

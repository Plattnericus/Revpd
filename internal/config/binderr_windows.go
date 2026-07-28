//go:build windows

package config

import "syscall"

// Winsock has its own numbers for the same three conditions, and a bind on
// Windows fails with those rather than the POSIX ones. Without this the reason
// falls through to the operating system's own sentence — which is written in
// whatever language the machine is set to, and says nothing a log reader can
// act on.
//
// Only WSAEACCES has a name in the standard library; the other two are spelled
// out here rather than pulled in from x/sys for two constants.
const (
	wsaEAddrInUse    = syscall.Errno(10048)
	wsaEAddrNotAvail = syscall.Errno(10049)
)

var (
	errsInUse    = []error{wsaEAddrInUse, syscall.EADDRINUSE}
	errsDenied   = []error{syscall.WSAEACCES, syscall.EACCES, syscall.EPERM}
	errsNoSuchIP = []error{wsaEAddrNotAvail, syscall.EADDRNOTAVAIL}
)

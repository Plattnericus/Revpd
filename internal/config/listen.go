package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Bound is a listener together with the address it actually got, which is not
// always the one that was asked for.
type Bound struct {
	Listener net.Listener

	// Addr is the address that worked.
	Addr string

	// FellBack is true when Addr is not the first choice. The portal shows
	// this, because somebody who forwarded 443 needs to know it went elsewhere.
	FellBack bool

	// Tried lists every address that was refused, with the reason, so the
	// message can say what is holding the port rather than just "failed".
	Tried []string
}

// Listen binds the first address that works: the primary, then each fallback
// in turn.
//
// Falling back is deliberate. A gateway that refuses to start because port 443
// is taken is a gateway nobody can reach to fix it, and the alternative — the
// portal quietly not running — is worse than the portal running somewhere
// slightly unexpected and saying so loudly.
//
// A permission error is never retried on the same port: it means the process
// lacks CAP_NET_BIND_SERVICE, and the next privileged port would fail the same
// way. Unprivileged fallbacks are still tried, which is what makes this work
// when someone runs the binary by hand as themselves.
func Listen(network, primary string, fallbacks []string) (*Bound, error) {
	if primary == "" {
		return nil, errors.New("no address to listen on")
	}

	b := &Bound{}
	for i, addr := range append([]string{primary}, fallbacks...) {
		if addr == "" {
			continue
		}

		ln, err := net.Listen(network, addr)
		if err == nil {
			b.Listener = ln
			b.Addr = ln.Addr().String()
			b.FellBack = i > 0
			return b, nil
		}
		b.Tried = append(b.Tried, fmt.Sprintf("%s (%s)", addr, reason(err)))
	}

	return nil, fmt.Errorf("could not listen on any of: %s", strings.Join(b.Tried, ", "))
}

// reason turns a bind error into the thing that is actually wrong, because
// "address already in use" and "permission denied" need opposite fixes.
//
// The wording is ours rather than the operating system's. The same failure is
// phrased differently on every platform and translated into whatever language
// the machine is set to, and a log line somebody pastes into a bug report
// should say the same thing wherever it came from.
func reason(err error) string {
	switch {
	case isOneOf(err, errsInUse):
		return "already in use"
	case isOneOf(err, errsDenied):
		return "not permitted — a port below 1024 needs CAP_NET_BIND_SERVICE"
	case isOneOf(err, errsNoSuchIP):
		return "no such address on this machine"
	default:
		return err.Error()
	}
}

func isOneOf(err error, list []error) bool {
	for _, target := range list {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// Port returns just the port of a host:port address.
func Port(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// PortalURL is what to type into a browser to reach the portal. The port is
// left off when it is the one a browser assumes, so the common case reads as
// a plain hostname.
func PortalURL(hostname, listenAddr string) string {
	port := Port(listenAddr)
	if port == "" || port == "443" {
		return "https://" + hostname
	}
	return "https://" + net.JoinHostPort(hostname, port)
}

package netcheck

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

/*
	Is the port actually forwarded?

	The only way to know for certain is to knock from outside, and there is no
	outside to knock from — so this knocks on our own public address and reads
	what comes back. When the router loops the connection round (hairpin NAT)
	a success is proof the whole path works: forward, firewall, listener.

	A failure proves much less. Plenty of routers refuse to hairpin at all, and
	from the inside that looks exactly like a missing port forward. So a
	failure is reported as unconfirmed rather than broken. Saying "your port
	forward is wrong" to somebody whose setup is fine would send them off
	changing things that were already right.

	The probe opens a connection and closes it without sending a byte. It takes
	no parameters: the address and ports come from the configuration, so this
	cannot be pointed at anything else.
*/

// Reach is the outcome of one knock.
type Reach string

const (
	// ReachOpen is the only result that proves anything. Something accepted
	// the connection on the public address.
	ReachOpen Reach = "open"

	// ReachRefused means something answered and said no. Usually the router
	// itself, either because the forward is missing or because it will not
	// loop a connection back inside.
	ReachRefused Reach = "refused"

	// ReachTimeout means nothing answered at all, which is what a router that
	// silently drops hairpinned traffic looks like.
	ReachTimeout Reach = "timeout"

	// ReachSkipped means there was nothing sensible to knock on.
	ReachSkipped Reach = "skipped"

	// ReachError is anything else — no route, DNS, an address family the
	// machine cannot use.
	ReachError Reach = "error"
)

// Confirmed reports whether this outcome proves the path works. Only an
// accepted connection does.
func (r Reach) Confirmed() bool { return r == ReachOpen }

// ProbeResult is one port checked.
type ProbeResult struct {
	Address string `json:"address"`
	Reach   Reach  `json:"reach"`
	Detail  string `json:"detail,omitempty"`

	// Took is how long the knock lasted, which is the difference between a
	// firewall that dropped it and one that answered.
	TookMS int64 `json:"took_ms"`
}

// Confirmed is Reach.Confirmed, hoisted so the JSON carries it too.
func (p ProbeResult) Confirmed() bool { return p.Reach.Confirmed() }

// Probe knocks once on host:port.
//
// Only public addresses are probed. That is not caution for its own sake: a
// probe aimed inside would turn an administrator button into a way to scan the
// local network from the gateway, and the answer would be meaningless anyway.
func Probe(ctx context.Context, host string, port int, timeout time.Duration) ProbeResult {
	if host == "" || port <= 0 || port > 65535 {
		return ProbeResult{Reach: ReachSkipped, Detail: "no public address is known yet"}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	res := ProbeResult{Address: address}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve first, so a domain pointing at a LAN address is caught before
	// anything is dialled.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		res.Reach, res.Detail = ReachError, "could not look up "+host+": "+err.Error()
		return res
	}

	var target net.IP
	for _, ip := range ips {
		if IsPublic(ip) {
			target = ip
			break
		}
	}
	if target == nil {
		res.Reach = ReachSkipped
		res.Detail = host + " does not resolve to a public address, so there is nothing to check from here"
		return res
	}

	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target.String(), strconv.Itoa(port)))
	res.TookMS = time.Since(started).Milliseconds()

	if err == nil {
		// Nothing is sent. The listener on the other end is ours, and a
		// half-spoken RDP handshake would only make noise in the log.
		conn.Close()
		res.Reach = ReachOpen
		return res
	}

	res.Detail = err.Error()
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		res.Reach = ReachRefused
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		res.Reach = ReachTimeout
	default:
		res.Reach = ReachError
	}
	return res
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

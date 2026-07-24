package rdgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

/*
   The tunnel state machine.

   MS-TSGU is a fixed sequence: handshake, tunnel create, tunnel auth, channel
   create, then data. Each step is only accepted in its turn, so a client
   cannot skip the token check by jumping straight to a channel.
*/

type state int

const (
	stateHandshake state = iota
	stateTunnelCreate
	stateTunnelAuth
	stateChannelCreate
	stateReady
	stateClosed
)

func (s state) String() string {
	switch s {
	case stateHandshake:
		return "handshake"
	case stateTunnelCreate:
		return "tunnel create"
	case stateTunnelAuth:
		return "tunnel auth"
	case stateChannelCreate:
		return "channel create"
	case stateReady:
		return "ready"
	default:
		return "closed"
	}
}

// Authorizer resolves the PAA cookie a client presents. It is the same token
// the portal issues after MFA, so the gateway never authenticates here itself.
type Authorizer interface {
	// AuthorizeTunnel checks the cookie and returns the backend the client may
	// reach. An error means the tunnel is refused, and the reason is never
	// passed on to the client.
	AuthorizeTunnel(ctx context.Context, srcIP net.IP, cookie string) (backend string, err error)
}

var errRefused = errors.New("tunnel refused")

// Tunnel drives one client connection through the sequence.
type Tunnel struct {
	auth  Authorizer
	srcIP net.IP

	state   state
	cookie  string
	backend string

	// Requested is the machine the client named in the channel create. It is
	// recorded for the audit trail but never trusted: the backend comes from
	// the token, not from what the client asked for.
	Requested []string
}

func NewTunnel(auth Authorizer, srcIP net.IP) *Tunnel {
	return &Tunnel{auth: auth, srcIP: srcIP, state: stateHandshake}
}

// Backend is the address to forward to, valid once Ready reports true.
func (t *Tunnel) Backend() string { return t.backend }

func (t *Tunnel) Ready() bool { return t.state == stateReady }

// Handle processes one packet and returns what to send back.
//
// A nil reply with no error means the packet needed no answer. Once the tunnel
// is ready, data packets are handed to the caller through payload instead.
func (t *Tunnel) Handle(ctx context.Context, p *Packet) (reply []byte, payload []byte, err error) {
	// Keepalives are valid at any point and change nothing.
	if p.Type == PktKeepalive {
		return nil, nil, nil
	}

	switch t.state {
	case stateHandshake:
		if p.Type != PktHandshakeRequest {
			return nil, nil, fmt.Errorf("%w: got 0x%04x during %s", ErrSequence, p.Type, t.state)
		}
		req, err := ParseHandshakeRequest(p.Body)
		if err != nil {
			return nil, nil, err
		}

		// Insist on PAA. Without it there is no token, and a tunnel with no
		// token is an open proxy.
		if req.ExtendedAuth&AuthPAA == 0 {
			slog.Warn("rdgw client offers no PAA", "src", t.srcIP, "offered", req.ExtendedAuth)
			return BuildHandshakeResponse(StatusNotSupported, AuthPAA), nil, errRefused
		}

		t.state = stateTunnelCreate
		return BuildHandshakeResponse(StatusSuccess, AuthPAA), nil, nil

	case stateTunnelCreate:
		if p.Type != PktTunnelCreate {
			return nil, nil, fmt.Errorf("%w: got 0x%04x during %s", ErrSequence, p.Type, t.state)
		}
		req, err := ParseTunnelCreate(p.Body)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(req.Cookie) == "" {
			return BuildTunnelResponse(StatusAccessDenied, 0, 0), nil, errRefused
		}

		backend, err := t.auth.AuthorizeTunnel(ctx, t.srcIP, req.Cookie)
		if err != nil || backend == "" {
			// Same answer whether the token was unknown, spent or expired.
			return BuildTunnelResponse(StatusAccessDenied, 0, 0), nil, errRefused
		}

		t.cookie = req.Cookie
		t.backend = backend
		t.state = stateTunnelAuth

		return BuildTunnelResponse(StatusSuccess, 1, CapabilityIdle|CapabilityMessaging), nil, nil

	case stateTunnelAuth:
		if p.Type != PktTunnelAuth {
			return nil, nil, fmt.Errorf("%w: got 0x%04x during %s", ErrSequence, p.Type, t.state)
		}
		if _, err := ParseTunnelAuth(p.Body); err != nil {
			return nil, nil, err
		}

		t.state = stateChannelCreate
		return BuildTunnelAuthResponse(StatusSuccess), nil, nil

	case stateChannelCreate:
		if p.Type != PktChannelCreate {
			return nil, nil, fmt.Errorf("%w: got 0x%04x during %s", ErrSequence, p.Type, t.state)
		}
		req, err := ParseChannelCreate(p.Body)
		if err != nil {
			return nil, nil, err
		}

		// Recorded, not obeyed. Honouring it would turn the gateway into an
		// open proxy for anyone holding one valid token.
		t.Requested = req.Resources

		t.state = stateReady
		return BuildChannelResponse(StatusSuccess, 1), nil, nil

	case stateReady:
		switch p.Type {
		case PktData:
			data, err := ParseData(p.Body)
			if err != nil {
				return nil, nil, err
			}
			return nil, data, nil

		case PktCloseChannel:
			t.state = stateClosed
			return BuildCloseChannelResponse(StatusSuccess), nil, nil

		default:
			// Service and reauth messages are the server's to send, not the
			// client's. Ignore rather than tear the tunnel down.
			return nil, nil, nil
		}

	default:
		return nil, nil, fmt.Errorf("%w: packet after close", ErrSequence)
	}
}

// Refused reports whether an error means the client was turned away rather
// than something going wrong, so the caller can log it at the right level.
func Refused(err error) bool { return errors.Is(err, errRefused) }

// Package rdgw implements the Remote Desktop Gateway protocol, MS-TSGU.
//
// It exists for networks where 3389 cannot be exposed at all: the client
// tunnels RDP inside HTTPS on 443 instead. The gateway authenticates the
// tunnel with a token this server issued after MFA, then forwards the inner
// RDP stream to the target exactly as the plain relay does.
//
// Only the packet layer and the tunnel state machine live here. What carries
// the packets — WebSocket or the older RPC-over-HTTP — is the transport's
// business and is deliberately kept separate.
package rdgw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

var (
	ErrShort     = errors.New("packet is truncated")
	ErrTooLarge  = errors.New("packet is implausibly large")
	ErrUnknown   = errors.New("unknown packet type")
	ErrSequence  = errors.New("packet arrived out of sequence")
	ErrMalformed = errors.New("malformed packet")
)

// MaxPacket caps what we buffer from a peer that has not authenticated yet.
// Data packets carry RDP payload and are the only ones that get near this.
const MaxPacket = 64 * 1024

// Packet types, MS-TSGU 2.2.3.1.
const (
	PktHandshakeRequest  uint16 = 0x0001
	PktHandshakeResponse uint16 = 0x0002
	PktExtendedAuth      uint16 = 0x0003
	PktTunnelCreate      uint16 = 0x0004
	PktTunnelResponse    uint16 = 0x0005
	PktTunnelAuth        uint16 = 0x0006
	PktTunnelAuthResponse uint16 = 0x0007
	PktChannelCreate     uint16 = 0x0008
	PktChannelResponse   uint16 = 0x0009
	PktData              uint16 = 0x000A
	PktServiceMessage    uint16 = 0x000B
	PktReauth            uint16 = 0x000C
	PktKeepalive         uint16 = 0x000D
	PktCloseChannel      uint16 = 0x0010
	PktCloseChannelResp  uint16 = 0x0011
)

// Error codes the client understands. Anything non-zero aborts the tunnel.
const (
	StatusSuccess          uint32 = 0x00000000
	StatusAccessDenied     uint32 = 0x00000005
	StatusInvalidParameter uint32 = 0x00000057
	StatusNotSupported     uint32 = 0x00000032
)

// Capability flags advertised in the handshake, MS-TSGU 2.2.5.3.1.
const (
	CapabilityIdle      uint16 = 0x0001
	CapabilityMessaging uint16 = 0x0002
	CapabilityReauth    uint16 = 0x0004
)

// Extended authentication methods. PAA is the one that matters: it carries
// the cookie this gateway issued after MFA.
const (
	AuthNone uint16 = 0x0000
	AuthSC   uint16 = 0x0001 // smartcard
	AuthPAA  uint16 = 0x0002 // pluggable, i.e. our token
)

// Header is the four-field prefix every packet carries, MS-TSGU 2.2.10.10.
type Header struct {
	Type   uint16
	Length uint32
}

const headerSize = 8

// Packet is a header plus its body, which excludes the header itself.
type Packet struct {
	Type uint16
	Body []byte
}

// ParsePacket reads one packet from the front of b and reports how many bytes
// it consumed, so a caller streaming bytes can find the next one.
func ParsePacket(b []byte) (*Packet, int, error) {
	if len(b) < headerSize {
		return nil, 0, ErrShort
	}

	typ := binary.LittleEndian.Uint16(b[0:2])
	// b[2:4] is reserved and ignored.
	length := binary.LittleEndian.Uint32(b[4:8])

	if length < headerSize {
		return nil, 0, fmt.Errorf("%w: length %d is below the header size", ErrMalformed, length)
	}
	if length > MaxPacket {
		return nil, 0, fmt.Errorf("%w: length %d", ErrTooLarge, length)
	}
	if uint32(len(b)) < length {
		return nil, 0, ErrShort
	}

	return &Packet{Type: typ, Body: b[headerSize:length]}, int(length), nil
}

// Build wraps a body in the packet header.
func Build(typ uint16, body []byte) []byte {
	out := make([]byte, headerSize, headerSize+len(body))
	binary.LittleEndian.PutUint16(out[0:2], typ)
	binary.LittleEndian.PutUint32(out[4:8], uint32(headerSize+len(body)))
	return append(out, body...)
}

/* ------------------------------------------------------------ handshake --- */

// HandshakeRequest is what the client opens with, MS-TSGU 2.2.5.3.1.
type HandshakeRequest struct {
	VersionMajor uint8
	VersionMinor uint8
	ClientVersion uint16
	ExtendedAuth uint16
}

func ParseHandshakeRequest(body []byte) (*HandshakeRequest, error) {
	if len(body) < 6 {
		return nil, fmt.Errorf("%w: handshake request is %d bytes", ErrShort, len(body))
	}
	return &HandshakeRequest{
		VersionMajor:  body[0],
		VersionMinor:  body[1],
		ClientVersion: binary.LittleEndian.Uint16(body[2:4]),
		ExtendedAuth:  binary.LittleEndian.Uint16(body[4:6]),
	}, nil
}

// BuildHandshakeResponse answers the handshake, MS-TSGU 2.2.5.3.2.
//
// The extended auth field has to echo something the client offered, or it
// gives up without saying why.
func BuildHandshakeResponse(status uint32, extendedAuth uint16) []byte {
	body := make([]byte, 10)
	binary.LittleEndian.PutUint32(body[0:4], status)
	body[4] = 1 // version major
	body[5] = 0 // version minor
	binary.LittleEndian.PutUint16(body[6:8], 0x0001)
	binary.LittleEndian.PutUint16(body[8:10], extendedAuth)
	return Build(PktHandshakeResponse, body)
}

/* --------------------------------------------------------------- tunnel --- */

// TunnelCreate carries the PAA cookie, which is where our token arrives.
type TunnelCreate struct {
	Capabilities uint32
	Cookie       string
}

// Field presence flags in a tunnel create request, MS-TSGU 2.2.5.3.3.
const (
	tunnelFieldPAACookie uint16 = 0x0001
	tunnelFieldReauth    uint16 = 0x0002
)

func ParseTunnelCreate(body []byte) (*TunnelCreate, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("%w: tunnel create is %d bytes", ErrShort, len(body))
	}

	out := &TunnelCreate{Capabilities: binary.LittleEndian.Uint32(body[0:4])}
	fields := binary.LittleEndian.Uint16(body[4:6])
	// body[6:8] is reserved.

	rest := body[8:]

	if fields&tunnelFieldPAACookie != 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("%w: cookie length is missing", ErrShort)
		}
		// Length is in bytes and the string is UTF-16.
		n := int(binary.LittleEndian.Uint16(rest[0:2]))
		rest = rest[2:]

		if n < 0 || n > len(rest) {
			return nil, fmt.Errorf("%w: cookie claims %d bytes, %d left", ErrMalformed, n, len(rest))
		}
		out.Cookie = decodeUTF16(rest[:n])
	}
	return out, nil
}

// BuildTunnelResponse answers a tunnel create, MS-TSGU 2.2.5.3.4.
func BuildTunnelResponse(status uint32, tunnelID uint32, capabilities uint16) []byte {
	body := make([]byte, 18)

	binary.LittleEndian.PutUint16(body[0:2], 0x0001) // server version
	binary.LittleEndian.PutUint32(body[2:6], status)
	binary.LittleEndian.PutUint32(body[6:10], tunnelID)
	binary.LittleEndian.PutUint32(body[10:14], 0) // no optional fields

	// Capabilities follow as a consent-message-free block.
	binary.LittleEndian.PutUint16(body[14:16], capabilities)
	binary.LittleEndian.PutUint16(body[16:18], 0)

	return Build(PktTunnelResponse, body)
}

/* ---------------------------------------------------------- tunnel auth --- */

// TunnelAuth names the client machine, MS-TSGU 2.2.5.3.5.
type TunnelAuth struct {
	ClientName string
}

func ParseTunnelAuth(body []byte) (*TunnelAuth, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("%w: tunnel auth is %d bytes", ErrShort, len(body))
	}

	n := int(binary.LittleEndian.Uint16(body[0:2]))
	rest := body[2:]
	if n < 0 || n > len(rest) {
		return nil, fmt.Errorf("%w: client name claims %d bytes, %d left", ErrMalformed, n, len(rest))
	}
	return &TunnelAuth{ClientName: decodeUTF16(rest[:n])}, nil
}

// BuildTunnelAuthResponse answers, MS-TSGU 2.2.5.3.6.
//
// The timeouts are all zero: this gateway does its own idle handling in the
// relay, and a second layer of it would only fight with the first.
func BuildTunnelAuthResponse(status uint32) []byte {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:4], status)
	binary.LittleEndian.PutUint32(body[4:8], 0)  // flags
	binary.LittleEndian.PutUint32(body[8:12], 0) // idle timeout
	binary.LittleEndian.PutUint32(body[12:16], 0)
	return Build(PktTunnelAuthResponse, body)
}

/* -------------------------------------------------------------- channel --- */

// ChannelCreate names the machine the client wants, MS-TSGU 2.2.5.3.7.
type ChannelCreate struct {
	Resources []string
	Port      uint16
	Protocol  uint16
}

func ParseChannelCreate(body []byte) (*ChannelCreate, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: channel create is %d bytes", ErrShort, len(body))
	}

	count := int(body[0])
	// body[1] is the alternate resource count, which we do not use.
	out := &ChannelCreate{
		Port:     binary.LittleEndian.Uint16(body[2:4]),
		Protocol: 0,
	}

	if count < 0 || count > 16 {
		return nil, fmt.Errorf("%w: %d resources named", ErrMalformed, count)
	}

	rest := body[4:]
	for i := 0; i < count; i++ {
		if len(rest) < 2 {
			return nil, fmt.Errorf("%w: resource %d has no length", ErrShort, i)
		}
		n := int(binary.LittleEndian.Uint16(rest[0:2]))
		rest = rest[2:]

		if n < 0 || n > len(rest) {
			return nil, fmt.Errorf("%w: resource %d claims %d bytes, %d left", ErrMalformed, i, n, len(rest))
		}
		out.Resources = append(out.Resources, decodeUTF16(rest[:n]))
		rest = rest[n:]
	}
	return out, nil
}

// BuildChannelResponse answers, MS-TSGU 2.2.5.3.8.
func BuildChannelResponse(status uint32, channelID uint32) []byte {
	body := make([]byte, 14)
	binary.LittleEndian.PutUint32(body[0:4], status)
	binary.LittleEndian.PutUint32(body[4:8], 0) // no optional fields
	binary.LittleEndian.PutUint32(body[8:12], channelID)
	binary.LittleEndian.PutUint16(body[12:14], 0)
	return Build(PktChannelResponse, body)
}

/* ----------------------------------------------------------------- data --- */

// ParseData unwraps an RDP payload, MS-TSGU 2.2.5.3.9.
func ParseData(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("%w: data packet is %d bytes", ErrShort, len(body))
	}

	n := int(binary.LittleEndian.Uint16(body[0:2]))
	rest := body[2:]
	if n < 0 || n > len(rest) {
		return nil, fmt.Errorf("%w: data claims %d bytes, %d left", ErrMalformed, n, len(rest))
	}
	return rest[:n], nil
}

// BuildData wraps an RDP payload for the client.
func BuildData(payload []byte) []byte {
	body := make([]byte, 2, 2+len(payload))
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(payload)))
	return Build(PktData, append(body, payload...))
}

func BuildCloseChannelResponse(status uint32) []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:4], status)
	return Build(PktCloseChannelResp, body)
}

/* ---------------------------------------------------------------- utf16 --- */

// decodeUTF16 turns a little-endian UTF-16 field into Go text, stopping at the
// first null so trailing padding never leaks into a hostname or a token.
func decodeUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

func encodeUTF16(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

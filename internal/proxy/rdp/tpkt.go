// Package rdp implements just enough of an RDP server to log a user in.
//
// Scope on purpose: we take the connection far enough to read the credentials
// out of the Client Info PDU, then hand the client off to the real machine
// with a Server Redirection PDU. There is no graphics, no input handling and
// no capability negotiation beyond what the client insists on.
//
// Everything here follows MS-RDPBCGR. Section numbers are quoted where the
// layout is not obvious from the code.
package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrProtocol = errors.New("rdp protocol error")
	ErrTooLarge = errors.New("rdp pdu too large")
)

// MaxPDU caps what we are willing to buffer from an unauthenticated peer.
// Real PDUs in this phase are a few hundred bytes.
const MaxPDU = 16 * 1024

const tpktVersion = 3

// readTPKT reads one TPKT frame and returns its payload, without the 4-byte
// header. See [T123] section 8.
func readTPKT(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("read tpkt header: %w", err)
	}

	if head[0] != tpktVersion {
		return nil, fmt.Errorf("%w: tpkt version 0x%02x", ErrProtocol, head[0])
	}

	total := int(binary.BigEndian.Uint16(head[2:4]))
	if total < 4 {
		return nil, fmt.Errorf("%w: tpkt length %d", ErrProtocol, total)
	}
	if total > MaxPDU {
		return nil, fmt.Errorf("%w: tpkt length %d", ErrTooLarge, total)
	}

	body := make([]byte, total-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read tpkt body: %w", err)
	}
	return body, nil
}

// writeTPKT wraps a payload in a TPKT frame and sends it.
func writeTPKT(w io.Writer, payload []byte) error {
	total := len(payload) + 4
	if total > 0xFFFF {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, total)
	}

	frame := make([]byte, 4, total)
	frame[0] = tpktVersion
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	frame = append(frame, payload...)

	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("write tpkt: %w", err)
	}
	return nil
}

/* --------------------------------------------------------------- x.224 --- */

// Security protocols the client offers in rdpNegReq, MS-RDPBCGR 2.2.1.1.1.
const (
	ProtocolRDP    uint32 = 0x00000000
	ProtocolSSL    uint32 = 0x00000001
	ProtocolHybrid uint32 = 0x00000002
	ProtocolRDSTLS uint32 = 0x00000004
)

// rdpNegReq / rdpNegRsp / rdpNegFailure type codes.
const (
	negTypeRequest = 0x01
	negTypeRsp     = 0x02
	negTypeFailure = 0x03
)

// Negotiation failure codes, MS-RDPBCGR 2.2.1.2.2.
const (
	failSSLRequiredByServer   uint32 = 0x00000001
	failSSLNotAllowedByServer uint32 = 0x00000002
	failHybridRequired        uint32 = 0x00000005
)

// negRequest is what the client asked for in its connection request.
type negRequest struct {
	present   bool
	flags     byte
	protocols uint32
}

// parseNegRequest pulls the optional rdpNegReq out of the variable part of a
// connection request. Absent means the client only speaks legacy RDP security.
func parseNegRequest(variable []byte) negRequest {
	// Skip a cookie or routing token if one is there; both end with \r\n.
	for i := 0; i+1 < len(variable); i++ {
		if variable[i] == '\r' && variable[i+1] == '\n' {
			variable = variable[i+2:]
			break
		}
	}

	if len(variable) < 8 || variable[0] != negTypeRequest {
		return negRequest{}
	}
	return negRequest{
		present:   true,
		flags:     variable[1],
		protocols: binary.LittleEndian.Uint32(variable[4:8]),
	}
}

// writeConnectionConfirm answers the connection request, telling the client
// which security protocol we picked.
//
// We always pick TLS. NLA would hide the credentials from us inside CredSSP,
// which is exactly what this gateway needs to see.
func writeConnectionConfirm(w io.Writer, selected uint32) error {
	// x224Crq: length indicator, CC code, dst-ref, src-ref, class.
	body := []byte{
		0x0E,             // length indicator: 14 bytes follow
		0xD0,             // CC TPDU
		0x00, 0x00,       // dst-ref
		0x00, 0x00,       // src-ref
		0x00,             // class 0
		negTypeRsp,       // RDP_NEG_RSP
		0x00,             // flags
		0x08, 0x00,       // length, always 8
		0x00, 0x00, 0x00, 0x00, // selectedProtocol, filled below
	}
	binary.LittleEndian.PutUint32(body[11:15], selected)

	return writeTPKT(w, body)
}

// writeNegotiationFailure tells the client why we will not continue. Sending
// this is much friendlier than dropping the socket: mstsc shows a real reason.
func writeNegotiationFailure(w io.Writer, code uint32) error {
	body := []byte{
		0x0E,
		0xD0,
		0x00, 0x00,
		0x00, 0x00,
		0x00,
		negTypeFailure,
		0x00,
		0x08, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint32(body[11:15], code)

	return writeTPKT(w, body)
}

/* ---------------------------------------------------------------- util --- */

// cursor walks a byte slice without panicking on short input, which matters
// because everything here comes from an unauthenticated peer.
type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) fail(format string, args ...any) {
	if c.err == nil {
		c.err = fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
	}
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if n < 0 || c.remaining() < n {
		c.fail("wanted %d bytes, %d left", n, c.remaining())
		return make([]byte, max(n, 0))
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out
}

func (c *cursor) u8() byte {
	b := c.take(1)
	return b[0]
}

func (c *cursor) u16le() uint16 {
	return binary.LittleEndian.Uint16(c.take(2))
}

func (c *cursor) u32le() uint32 {
	return binary.LittleEndian.Uint32(c.take(4))
}

func (c *cursor) skip(n int) { c.take(n) }

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

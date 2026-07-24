// Package x224 reads just enough of the first RDP packet to learn who is calling.
//
// This is the only part of the stream revpd ever inspects, and it only reads.
// Everything after this byte range is forwarded untouched, which is what keeps
// NLA, clipboard and multi-monitor working end to end.
//
// Layout is MS-RDPBCGR 2.2.1.1:
//
//	tpktHeader      4 bytes   version, reserved, 2-byte big-endian length
//	x224Crq         7 bytes   length indicator, CR code, dst/src ref, class
//	routingToken    variable  optional, ends with \r\n     -- mutually exclusive
//	cookie          variable  optional, "Cookie: mstshash=NAME\r\n"  -- with this
//	rdpNegReq       8 bytes   optional
//	rdpCorrelation 36 bytes   optional
package x224

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrNotTPKT   = errors.New("not a TPKT packet")
	ErrNotCR     = errors.New("not an X.224 connection request")
	ErrTooLarge  = errors.New("connection request is implausibly large")
	ErrTruncated = errors.New("connection request is truncated")
)

const (
	tpktVersion = 3
	tpktHeader  = 4
	x224MinLen  = 7
	crCode      = 0xE0 // CR TPDU

	// A real CR is ~40 bytes. Anything near this is someone probing us.
	MaxCRSize = 2048

	cookiePrefix = "Cookie: mstshash="
)

// ConnectionRequest is what we learned from the first packet.
type ConnectionRequest struct {
	// Raw is the packet exactly as it arrived. It gets replayed to the backend
	// byte for byte -- rebuilding it would change the handshake.
	Raw []byte

	// Cookie is the mstshash identifier, empty when the client sent none.
	//
	// Anyone can put anything here. It is a routing hint for the approval
	// prompt and must never be treated as authentication.
	Cookie string

	// RoutingToken is set instead of Cookie by load-balanced deployments.
	RoutingToken string
}

// Read consumes exactly one connection request from r.
//
// It is deliberately strict: a client that cannot produce a well-formed CR has
// no business reaching the backend.
func Read(r *bufio.Reader) (*ConnectionRequest, error) {
	head, err := r.Peek(tpktHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTruncated, err)
	}

	if head[0] != tpktVersion {
		return nil, fmt.Errorf("%w: version byte 0x%02x", ErrNotTPKT, head[0])
	}

	length := int(binary.BigEndian.Uint16(head[2:4]))
	if length < tpktHeader+x224MinLen {
		return nil, fmt.Errorf("%w: length %d", ErrTruncated, length)
	}
	if length > MaxCRSize {
		return nil, fmt.Errorf("%w: length %d", ErrTooLarge, length)
	}

	raw := make([]byte, length)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTruncated, err)
	}

	// x224Crq: raw[4] is the length indicator, raw[5] the TPDU code.
	if raw[5] != crCode {
		return nil, fmt.Errorf("%w: tpdu code 0x%02x", ErrNotCR, raw[5])
	}

	// The length indicator counts the bytes after itself, so it must fit.
	if li := int(raw[4]); li+tpktHeader+1 > length {
		return nil, fmt.Errorf("%w: x224 length indicator %d overruns packet of %d", ErrTruncated, li, length)
	}

	cr := &ConnectionRequest{Raw: raw}

	// Variable part starts after the 7-byte x224Crq.
	body := raw[tpktHeader+x224MinLen:]
	if line, ok := firstLine(body); ok {
		switch {
		case strings.HasPrefix(line, cookiePrefix):
			cr.Cookie = sanitize(strings.TrimPrefix(line, cookiePrefix))
		case strings.HasPrefix(line, "Cookie: msts="):
			cr.RoutingToken = sanitize(strings.TrimPrefix(line, "Cookie: msts="))
		}
	}
	return cr, nil
}

// firstLine returns the bytes up to the first \r\n.
func firstLine(b []byte) (string, bool) {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return string(b[:i]), true
		}
	}
	return "", false
}

// sanitize strips anything that has no business in a username.
//
// This value reaches logs, the audit trail and the web UI, so control
// characters and oversized input get cut here rather than downstream.
func sanitize(s string) string {
	const maxLen = 64

	var b strings.Builder
	for _, r := range s {
		if len(b.String()) >= maxLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.' || r == '-' || r == '_' || r == '@' || r == '\\':
			b.WriteRune(r)
		}
	}
	return b.String()
}

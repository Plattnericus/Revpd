package rdp

import (
	"encoding/binary"
	"fmt"
)

// Minimal BER reader/writer for the MCS Connect Initial and Connect Response
// PDUs (T.125). Only the shapes those two PDUs use are covered — this is not a
// general ASN.1 implementation and is not meant to become one.

const (
	berTagBoolean    = 0x01
	berTagInteger    = 0x02
	berTagOctetStr   = 0x04
	berTagEnumerated = 0x0A
	berTagSequence   = 0x30
)

// Application-class tags used by T.125.
const (
	berTagConnectInitial  = 0x7F65 // application 101
	berTagConnectResponse = 0x7F66 // application 102
	berTagDomainParams    = 0x30   // sequence
)

/* --------------------------------------------------------------- write --- */

type berWriter struct {
	buf []byte
}

func (w *berWriter) raw(b []byte) { w.buf = append(w.buf, b...) }

// length writes a BER length in the shortest legal form.
func (w *berWriter) length(n int) {
	switch {
	case n < 0x80:
		w.buf = append(w.buf, byte(n))
	case n <= 0xFF:
		w.buf = append(w.buf, 0x81, byte(n))
	default:
		w.buf = append(w.buf, 0x82, byte(n>>8), byte(n))
	}
}

func (w *berWriter) tagged(tag byte, body []byte) {
	w.buf = append(w.buf, tag)
	w.length(len(body))
	w.raw(body)
}

// application writes a two-byte application-class tag.
func (w *berWriter) application(tag uint16, body []byte) {
	w.buf = append(w.buf, byte(tag>>8), byte(tag))
	w.length(len(body))
	w.raw(body)
}

func (w *berWriter) boolean(v bool) {
	b := byte(0x00)
	if v {
		b = 0xFF
	}
	w.tagged(berTagBoolean, []byte{b})
}

// integer writes the value in as few bytes as BER allows, but never fewer
// than one, and keeps it positive by prepending a zero when the top bit is set.
func (w *berWriter) integer(v uint32) {
	var body []byte
	switch {
	case v < 0x80:
		body = []byte{byte(v)}
	case v < 0x8000:
		body = []byte{byte(v >> 8), byte(v)}
	case v < 0x800000:
		body = []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		body = []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	w.tagged(berTagInteger, body)
}

func (w *berWriter) enumerated(v byte) { w.tagged(berTagEnumerated, []byte{v}) }

func (w *berWriter) octetString(b []byte) { w.tagged(berTagOctetStr, b) }

/* ---------------------------------------------------------------- read --- */

type berReader struct {
	c *cursor
}

// readLength decodes a BER length.
func (r *berReader) readLength() int {
	first := r.c.u8()
	if first < 0x80 {
		return int(first)
	}

	n := int(first & 0x7F)
	if n == 0 || n > 3 {
		r.c.fail("unsupported ber length of %d octets", n)
		return 0
	}

	var out int
	for _, b := range r.c.take(n) {
		out = out<<8 | int(b)
	}
	return out
}

// expectTag consumes a single-byte tag and returns the body length.
func (r *berReader) expectTag(tag byte) int {
	got := r.c.u8()
	if got != tag {
		r.c.fail("expected ber tag 0x%02x, got 0x%02x", tag, got)
		return 0
	}
	return r.readLength()
}

// expectApplication consumes a two-byte application tag.
func (r *berReader) expectApplication(tag uint16) int {
	hi, lo := r.c.u8(), r.c.u8()
	if uint16(hi)<<8|uint16(lo) != tag {
		r.c.fail("expected application tag 0x%04x, got 0x%02x%02x", tag, hi, lo)
		return 0
	}
	return r.readLength()
}

// skipValue reads past one tag-length-value.
func (r *berReader) skipValue() {
	tag := r.c.u8()
	// Two-byte application tags have the low five bits set.
	if tag&0x1F == 0x1F {
		r.c.u8()
	}
	n := r.readLength()
	r.c.skip(n)
}

func (r *berReader) octetString() []byte {
	n := r.expectTag(berTagOctetStr)
	return r.c.take(n)
}

func (r *berReader) err() error { return r.c.err }

/* ------------------------------------------------------- little helpers --- */

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// utf16le encodes a string the way RDP expects, without a terminator.
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			// Outside the BMP: encode as a surrogate pair.
			r -= 0x10000
			hi := uint16(0xD800 + (r >> 10))
			lo := uint16(0xDC00 + (r & 0x3FF))
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
			continue
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// utf16leZ is utf16le with the two-byte null RDP string fields carry.
func utf16leZ(s string) []byte {
	return append(utf16le(s), 0x00, 0x00)
}

// decodeUTF16 turns an RDP string field back into Go text, stopping at the
// first null so trailing padding never leaks into a username.
func decodeUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}

	out := make([]rune, 0, len(units))
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF && i+1 < len(units) {
			lo := units[i+1]
			if lo >= 0xDC00 && lo <= 0xDFFF {
				out = append(out, rune(u-0xD800)<<10|rune(lo-0xDC00)+0x10000)
				i++
				continue
			}
		}
		out = append(out, rune(u))
	}
	return string(out)
}

func fmtErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}

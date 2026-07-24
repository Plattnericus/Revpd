package rdp

// Packed Encoding Rules, the subset T.124 uses for the GCC Conference Create
// Request and Response. Byte-for-byte compatible with what mstsc sends and
// expects — the layouts follow the same order FreeRDP uses, because that is
// the reference that demonstrably interoperates.

// t124 object identifier {0 0 20 124 0 1}, encoded as PER wants it.
var t124OID = []byte{0x05, 0x00, 0x14, 0x7C, 0x00, 0x01}

// h221 keys tag which direction the user data belongs to.
var (
	h221ClientToServer = []byte("Duca")
	h221ServerToClient = []byte("McDn")
)

type perWriter struct {
	buf []byte
}

func (w *perWriter) raw(b []byte) { w.buf = append(w.buf, b...) }

func (w *perWriter) u8(v byte) { w.buf = append(w.buf, v) }

func (w *perWriter) u16be(v uint16) { w.buf = append(w.buf, byte(v>>8), byte(v)) }

// length uses the short form below 0x80 and a flagged 16-bit form above it.
func (w *perWriter) length(n int) {
	if n > 0x7F {
		w.u16be(uint16(n) | 0x8000)
		return
	}
	w.u8(byte(n))
}

func (w *perWriter) choice(c byte)    { w.u8(c) }
func (w *perWriter) selection(s byte) { w.u8(s) }

func (w *perWriter) objectIdentifier() { w.raw(t124OID) }

// numericString packs two digits per byte.
func (w *perWriter) numericString(s string, min int) {
	n := len(s)
	m := min
	if n >= min {
		m = n - min
	}
	w.length(m)

	for i := 0; i < n; i += 2 {
		c1 := (s[i] - 0x30) % 10
		var c2 byte
		if i+1 < n {
			c2 = (s[i+1] - 0x30) % 10
		}
		w.u8(c1<<4 | c2)
	}
}

func (w *perWriter) padding(n int) {
	for i := 0; i < n; i++ {
		w.u8(0)
	}
}

func (w *perWriter) numberOfSets(n byte) { w.u8(n) }

// integer16 is written relative to its declared minimum.
func (w *perWriter) integer16(v, min uint16) { w.u16be(v - min) }

func (w *perWriter) integer(v uint32) {
	switch {
	case v <= 0xFF:
		w.length(1)
		w.u8(byte(v))
	case v <= 0xFFFF:
		w.length(2)
		w.u16be(uint16(v))
	default:
		w.length(4)
		w.raw([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
}

func (w *perWriter) enumerated(v byte) { w.u8(v) }

func (w *perWriter) octetString(b []byte, min int) {
	n := len(b)
	m := min
	if n >= min {
		m = n - min
	}
	w.length(m)
	w.raw(b)
}

/* ---------------------------------------------------------------- read --- */

type perReader struct {
	c *cursor
}

func (r *perReader) length() int {
	first := r.c.u8()
	if first&0x80 != 0 {
		second := r.c.u8()
		return int(first&0x7F)<<8 | int(second)
	}
	return int(first)
}

// findUserData walks a Conference Create Request and returns the client data
// blocks. Rather than decode every PER field we only need to reach, we scan
// for the direction key and read the octet string that follows it — this is
// far more tolerant of the small layout differences between RDP clients.
func findUserData(body []byte) ([]byte, error) {
	idx := indexOf(body, h221ClientToServer)
	if idx < 0 {
		return nil, fmtErr("conference create request has no Duca key")
	}

	c := &cursor{b: body, pos: idx + len(h221ClientToServer)}
	r := &perReader{c: c}

	n := r.length()
	if c.err != nil {
		return nil, c.err
	}
	if n <= 0 || n > c.remaining() {
		return nil, fmtErr("user data length %d does not fit in %d bytes", n, c.remaining())
	}
	return c.take(n), c.err
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

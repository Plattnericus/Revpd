package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

/*
   A CBOR reader covering only what WebAuthn puts on the wire: the COSE_Key
   map and the attestation object wrapper.

   Deliberately not a general decoder. It refuses anything it does not
   recognise rather than skipping ahead, because this parses attacker-supplied
   bytes before the signature has been checked.
*/

var errCBOR = errors.New("cbor")

const (
	majUint   = 0
	majNegInt = 1
	majBytes  = 2
	majText   = 3
	majArray  = 4
	majMap    = 5
	majTag    = 6
	majSimple = 7
)

// maxItems bounds how much structure we will walk. Real values are tiny.
const maxItems = 1024

type reader struct {
	b   []byte
	pos int
}

func (r *reader) byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, fmt.Errorf("%w: out of bytes", errCBOR)
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, fmt.Errorf("%w: wanted %d bytes, %d left", errCBOR, n, len(r.b)-r.pos)
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

// head reads a major type and its argument.
func (r *reader) head() (major byte, arg uint64, err error) {
	c, err := r.byte()
	if err != nil {
		return 0, 0, err
	}

	major = c >> 5
	info := c & 0x1F

	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		b, err := r.byte()
		return major, uint64(b), err
	case info == 25:
		b, err := r.take(2)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint16(b)), nil
	case info == 26:
		b, err := r.take(4)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint32(b)), nil
	case info == 27:
		b, err := r.take(8)
		if err != nil {
			return 0, 0, err
		}
		return major, binary.BigEndian.Uint64(b), nil
	default:
		// Indefinite lengths and reserved values. Nothing WebAuthn sends uses
		// them, so refusing is safer than trying to cope.
		return 0, 0, fmt.Errorf("%w: unsupported additional info %d", errCBOR, info)
	}
}

// value decodes one item.
func (r *reader) value(depth int) (any, error) {
	if depth > 8 {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}

	major, arg, err := r.head()
	if err != nil {
		return nil, err
	}

	switch major {
	case majUint:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return int64(arg), nil

	case majNegInt:
		if arg > math.MaxInt64-1 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil

	case majBytes:
		if arg > maxItems*64 {
			return nil, fmt.Errorf("%w: byte string of %d is implausible", errCBOR, arg)
		}
		return r.take(int(arg))

	case majText:
		if arg > maxItems*64 {
			return nil, fmt.Errorf("%w: text string of %d is implausible", errCBOR, arg)
		}
		b, err := r.take(int(arg))
		return string(b), err

	case majArray:
		if arg > maxItems {
			return nil, fmt.Errorf("%w: array of %d items", errCBOR, arg)
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil

	case majMap:
		if arg > maxItems {
			return nil, fmt.Errorf("%w: map of %d pairs", errCBOR, arg)
		}
		out := map[any]any{}
		for i := uint64(0); i < arg; i++ {
			k, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			// Only keys we can compare; a byte-slice key would panic on use.
			switch k.(type) {
			case int64, string:
				out[k] = v
			default:
				return nil, fmt.Errorf("%w: unusable map key", errCBOR)
			}
		}
		return out, nil

	case majTag:
		// Skip the tag and take the value it wraps.
		return r.value(depth + 1)

	case majSimple:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		default:
			return nil, fmt.Errorf("%w: unsupported simple value %d", errCBOR, arg)
		}

	default:
		return nil, fmt.Errorf("%w: unsupported major type %d", errCBOR, major)
	}
}

// decodeCBORMap decodes a map with integer or string keys, which is the shape
// of both a COSE_Key and an attestation object.
func decodeCBORMap(b []byte) (map[any]any, error) {
	r := &reader{b: b}

	v, err := r.value(0)
	if err != nil {
		return nil, err
	}

	m, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: expected a map", errCBOR)
	}
	return m, nil
}

// extractAuthData pulls authData out of an attestation object.
//
// The attestation statement itself is ignored on purpose: we ask for
// attestation "none", so there is nothing to verify and nothing we would do
// with the make and model of the authenticator.
func extractAuthData(attestation []byte) ([]byte, error) {
	m, err := decodeCBORMap(attestation)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation object: %v", ErrMalformed, err)
	}

	raw, ok := m["authData"].([]byte)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("%w: attestation object has no authData", ErrMalformed)
	}
	return raw, nil
}

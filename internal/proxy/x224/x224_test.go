package x224_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/plattnericus/revpd/internal/proxy/x224"
)

// buildCR assembles a connection request the way mstsc does.
func buildCR(variable []byte) []byte {
	body := make([]byte, 7)
	body[0] = byte(6 + len(variable)) // length indicator: everything after this byte
	body[1] = 0xE0                    // CR TPDU
	body = append(body, variable...)

	total := 4 + len(body)
	pkt := make([]byte, 4, total)
	pkt[0] = 3
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	return append(pkt, body...)
}

func withCookie(name string) []byte {
	return buildCR([]byte("Cookie: mstshash=" + name + "\r\n"))
}

func read(t *testing.T, pkt []byte) (*x224.ConnectionRequest, error) {
	t.Helper()
	return x224.Read(bufio.NewReader(bytes.NewReader(pkt)))
}

func TestReadExtractsCookie(t *testing.T) {
	pkt := withCookie("felix")

	cr, err := read(t, pkt)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cr.Cookie != "felix" {
		t.Fatalf("cookie = %q, want felix", cr.Cookie)
	}
	if !bytes.Equal(cr.Raw, pkt) {
		t.Fatal("Raw does not match the bytes that came in")
	}
}

// mstsc leaves the cookie out when no username is stored. That is not an error,
// it just means JIT cannot route an approval.
func TestReadWithoutCookie(t *testing.T) {
	cr, err := read(t, buildCR([]byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cr.Cookie != "" {
		t.Fatalf("cookie = %q, want empty", cr.Cookie)
	}
}

func TestReadRoutingToken(t *testing.T) {
	cr, err := read(t, buildCR([]byte("Cookie: msts=3640205228.15629.0000\r\n")))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cr.RoutingToken == "" {
		t.Fatal("routing token was not picked up")
	}
	if cr.Cookie != "" {
		t.Fatalf("routing token leaked into Cookie: %q", cr.Cookie)
	}
}

// The cookie reaches logs and the UI, so injection attempts have to die here.
func TestCookieIsSanitized(t *testing.T) {
	cases := []struct{ in, want string }{
		{"felix", "felix"},
		{"DOMAIN\\felix", "DOMAIN\\felix"},
		{"felix@corp.local", "felix@corp.local"},
		{"fe\x00lix", "felix"},
		{"fe\nlix", "felix"},
		{"<script>alert(1)</script>", "scriptalert1script"},
		{"'; DROP TABLE users; --", "DROPTABLEusers--"},
		{"\x1b[31mred", "31mred"},
		{strings.Repeat("a", 500), strings.Repeat("a", 64)},
	}

	for _, tc := range cases {
		cr, err := read(t, withCookie(tc.in))
		if err != nil {
			t.Errorf("read(%q): %v", tc.in, err)
			continue
		}
		if cr.Cookie != tc.want {
			t.Errorf("cookie for %q = %q, want %q", tc.in, cr.Cookie, tc.want)
		}
	}
}

func TestReadRejectsMalformed(t *testing.T) {
	oversized := buildCR([]byte("Cookie: mstshash=x\r\n"))
	binary.BigEndian.PutUint16(oversized[2:4], 60000)

	notCR := withCookie("felix")
	notCR[5] = 0xD0 // CC instead of CR

	overrun := withCookie("felix")
	overrun[4] = 0xFF // length indicator past the end of the packet

	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, x224.ErrTruncated},
		{"short header", []byte{3, 0}, x224.ErrTruncated},
		{"wrong version", []byte{5, 0, 0, 11, 6, 0xE0, 0, 0, 0, 0, 0}, x224.ErrNotTPKT},
		{"length below minimum", []byte{3, 0, 0, 5, 0}, x224.ErrTruncated},
		{"length beyond cap", oversized, x224.ErrTooLarge},
		{"not a connection request", notCR, x224.ErrNotCR},
		{"length indicator overruns", overrun, x224.ErrTruncated},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := read(t, tc.pkt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A truncated packet must not leave us blocked forever waiting for the rest.
func TestReadTruncatedMidPacket(t *testing.T) {
	pkt := withCookie("felix")
	if _, err := read(t, pkt[:len(pkt)-4]); !errors.Is(err, x224.ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

// Whatever we hand the backend must be identical to what the client sent.
func TestRawIsByteIdentical(t *testing.T) {
	for _, name := range []string{"felix", "", "DOMAIN\\admin"} {
		pkt := withCookie(name)
		cr, err := read(t, pkt)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(cr.Raw, pkt) {
			t.Fatalf("Raw differs from input for %q", name)
		}
	}
}

// The parser faces the open internet before anything is authenticated, so it
// must never panic and never hang.
func FuzzRead(f *testing.F) {
	f.Add(withCookie("felix"))
	f.Add(buildCR([]byte("Cookie: msts=1.2.3\r\n")))
	f.Add(buildCR([]byte{0x01, 0x00, 0x08, 0x00}))
	f.Add([]byte{3, 0, 0, 11, 6, 0xE0, 0, 0, 0, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		cr, err := x224.Read(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}

		if len(cr.Raw) > x224.MaxCRSize {
			t.Fatalf("accepted %d bytes, over the %d cap", len(cr.Raw), x224.MaxCRSize)
		}
		if len(cr.Cookie) > 64 {
			t.Fatalf("cookie of %d chars escaped the length cap", len(cr.Cookie))
		}
		for _, r := range cr.Cookie {
			if r < 0x20 || r > 0x7E {
				t.Fatalf("control character %q survived sanitising", r)
			}
		}
		if !bytes.HasPrefix(data, cr.Raw) {
			t.Fatal("Raw is not a prefix of the input")
		}
	})
}

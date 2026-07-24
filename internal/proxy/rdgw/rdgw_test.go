package rdgw

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

/* --------------------------------------------------------------- doubles --- */

type fakeAuth struct {
	backend string
	err     error

	sawCookie string
	sawIP     net.IP
	calls     int
}

func (a *fakeAuth) AuthorizeTunnel(_ context.Context, srcIP net.IP, cookie string) (string, error) {
	a.calls++
	a.sawCookie = cookie
	a.sawIP = srcIP

	if a.err != nil {
		return "", a.err
	}
	return a.backend, nil
}

func newTunnel(t *testing.T, auth *fakeAuth) *Tunnel {
	t.Helper()
	return NewTunnel(auth, net.ParseIP("203.0.113.7"))
}

/* --------------------------------------------------------- client frames --- */

func handshakeRequest(extAuth uint16) *Packet {
	body := make([]byte, 6)
	body[0] = 1 // version major
	body[1] = 0
	binary.LittleEndian.PutUint16(body[2:4], 0x0001)
	binary.LittleEndian.PutUint16(body[4:6], extAuth)
	return &Packet{Type: PktHandshakeRequest, Body: body}
}

func tunnelCreate(cookie string) *Packet {
	enc := encodeUTF16(cookie)

	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint16(body[4:6], tunnelFieldPAACookie)

	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(enc)))

	body = append(body, length...)
	return &Packet{Type: PktTunnelCreate, Body: append(body, enc...)}
}

func tunnelAuth(name string) *Packet {
	enc := encodeUTF16(name)

	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(enc)))
	return &Packet{Type: PktTunnelAuth, Body: append(body, enc...)}
}

func channelCreate(resources ...string) *Packet {
	body := make([]byte, 4)
	body[0] = byte(len(resources))
	binary.LittleEndian.PutUint16(body[2:4], 3389)

	for _, r := range resources {
		enc := encodeUTF16(r)
		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(len(enc)))
		body = append(body, length...)
		body = append(body, enc...)
	}
	return &Packet{Type: PktChannelCreate, Body: body}
}

func dataPacket(payload []byte) *Packet {
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(payload)))
	return &Packet{Type: PktData, Body: append(body, payload...)}
}

// walk runs the tunnel up to and including the step named.
func walk(t *testing.T, tun *Tunnel, cookie string) error {
	t.Helper()
	ctx := context.Background()

	for _, p := range []*Packet{
		handshakeRequest(AuthPAA),
		tunnelCreate(cookie),
		tunnelAuth("CLIENT-PC"),
		channelCreate("pc-buero.lan"),
	} {
		if _, _, err := tun.Handle(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

/* ------------------------------------------------------------ the happy --- */

func TestFullTunnelSequence(t *testing.T) {
	auth := &fakeAuth{backend: "192.168.1.40:3389"}
	tun := newTunnel(t, auth)

	if err := walk(t, tun, "the-token"); err != nil {
		t.Fatalf("sequence: %v", err)
	}
	if !tun.Ready() {
		t.Fatal("tunnel is not ready after the full sequence")
	}
	if tun.Backend() != "192.168.1.40:3389" {
		t.Fatalf("backend = %q", tun.Backend())
	}
	if auth.sawCookie != "the-token" {
		t.Fatalf("authoriser saw cookie %q", auth.sawCookie)
	}
	if !auth.sawIP.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("authoriser saw address %v", auth.sawIP)
	}

	// Data now flows through.
	_, payload, err := tun.Handle(context.Background(), dataPacket([]byte("rdp bytes")))
	if err != nil {
		t.Fatalf("data: %v", err)
	}
	if string(payload) != "rdp bytes" {
		t.Fatalf("payload = %q", payload)
	}
}

// The backend comes from the token, never from what the client asked for.
// Otherwise one valid token would turn the gateway into an open proxy.
func TestRequestedResourceDoesNotChooseTheBackend(t *testing.T) {
	auth := &fakeAuth{backend: "192.168.1.40:3389"}
	tun := newTunnel(t, auth)

	if err := walk(t, tun, "the-token"); err != nil {
		t.Fatalf("sequence: %v", err)
	}

	// The client named a completely different machine.
	tun2 := newTunnel(t, auth)
	ctx := context.Background()
	tun2.Handle(ctx, handshakeRequest(AuthPAA))
	tun2.Handle(ctx, tunnelCreate("the-token"))
	tun2.Handle(ctx, tunnelAuth("CLIENT-PC"))
	tun2.Handle(ctx, channelCreate("10.0.0.1", "some-other-host"))

	if tun2.Backend() != "192.168.1.40:3389" {
		t.Fatalf("backend = %q — the client's request changed the destination", tun2.Backend())
	}
	if len(tun2.Requested) != 2 {
		t.Fatalf("recorded %d requested resources, want 2 for the audit trail", len(tun2.Requested))
	}
}

/* ------------------------------------------------------------- refusals --- */

func TestUnknownTokenIsRefused(t *testing.T) {
	auth := &fakeAuth{err: errors.New("no such token")}
	tun := newTunnel(t, auth)
	ctx := context.Background()

	tun.Handle(ctx, handshakeRequest(AuthPAA))

	reply, _, err := tun.Handle(ctx, tunnelCreate("made-up"))
	if !Refused(err) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if tun.Ready() {
		t.Fatal("tunnel became ready despite an unknown token")
	}

	// The refusal must reach the client as access denied.
	p, _, perr := ParsePacket(reply)
	if perr != nil {
		t.Fatalf("parse reply: %v", perr)
	}
	if binary.LittleEndian.Uint32(p.Body[2:6]) != StatusAccessDenied {
		t.Fatal("refusal did not come back as access denied")
	}
}

func TestEmptyCookieIsRefused(t *testing.T) {
	auth := &fakeAuth{backend: "192.168.1.40:3389"}
	tun := newTunnel(t, auth)
	ctx := context.Background()

	tun.Handle(ctx, handshakeRequest(AuthPAA))

	if _, _, err := tun.Handle(ctx, tunnelCreate("   ")); !Refused(err) {
		t.Fatalf("err = %v, want a refusal for a blank cookie", err)
	}
	if auth.calls != 0 {
		t.Fatal("a blank cookie was sent to the authoriser")
	}
}

// Without PAA there is no token, and a tunnel with no token is an open proxy.
func TestClientWithoutPAAIsRefused(t *testing.T) {
	tun := newTunnel(t, &fakeAuth{backend: "192.168.1.40:3389"})

	if _, _, err := tun.Handle(context.Background(), handshakeRequest(AuthNone)); !Refused(err) {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

/* ------------------------------------------------------------ sequence --- */

// Every step must be refused out of turn. Skipping to a channel would bypass
// the token check entirely.
func TestStepsMustComeInOrder(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		send *Packet
	}{
		{"channel create first", channelCreate("pc")},
		{"tunnel create first", tunnelCreate("token")},
		{"tunnel auth first", tunnelAuth("pc")},
		{"data first", dataPacket([]byte("x"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun := newTunnel(t, &fakeAuth{backend: "192.168.1.40:3389"})

			_, _, err := tun.Handle(ctx, tc.send)
			if !errors.Is(err, ErrSequence) {
				t.Fatalf("err = %v, want ErrSequence", err)
			}
			if tun.Ready() {
				t.Fatal("tunnel became ready out of sequence")
			}
		})
	}
}

// Data before the tunnel is authorised must never be forwarded.
func TestDataBeforeAuthorisationIsRefused(t *testing.T) {
	tun := newTunnel(t, &fakeAuth{backend: "192.168.1.40:3389"})
	ctx := context.Background()

	tun.Handle(ctx, handshakeRequest(AuthPAA))

	_, payload, err := tun.Handle(ctx, dataPacket([]byte("secret")))
	if err == nil {
		t.Fatal("data was accepted before the token was checked")
	}
	if payload != nil {
		t.Fatal("a payload was handed out before authorisation")
	}
}

func TestKeepaliveIsAlwaysAccepted(t *testing.T) {
	tun := newTunnel(t, &fakeAuth{backend: "192.168.1.40:3389"})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, _, err := tun.Handle(ctx, &Packet{Type: PktKeepalive}); err != nil {
			t.Fatalf("keepalive at step %d: %v", i, err)
		}
	}
	// And it must not have advanced anything.
	if _, _, err := tun.Handle(ctx, tunnelCreate("token")); !errors.Is(err, ErrSequence) {
		t.Fatal("keepalives advanced the state machine")
	}
}

/* -------------------------------------------------------------- framing --- */

func TestPacketRoundTrip(t *testing.T) {
	raw := Build(PktData, []byte("hello"))

	p, n, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("consumed %d of %d bytes", n, len(raw))
	}
	if p.Type != PktData || string(p.Body) != "hello" {
		t.Fatalf("round trip gave type 0x%04x body %q", p.Type, p.Body)
	}
}

// Two packets in one buffer must be read one at a time.
func TestParsePacketFindsTheNextOne(t *testing.T) {
	buf := append(Build(PktKeepalive, nil), Build(PktData, []byte("second"))...)

	first, n, err := ParsePacket(buf)
	if err != nil || first.Type != PktKeepalive {
		t.Fatalf("first packet: %v type 0x%04x", err, first.Type)
	}

	second, _, err := ParsePacket(buf[n:])
	if err != nil || string(second.Body) != "second" {
		t.Fatalf("second packet: %v body %q", err, second.Body)
	}
}

func TestParsePacketRejectsGarbage(t *testing.T) {
	oversized := Build(PktData, []byte("x"))
	binary.LittleEndian.PutUint32(oversized[4:8], MaxPacket+1)

	tooShortLength := Build(PktData, nil)
	binary.LittleEndian.PutUint32(tooShortLength[4:8], 2)

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"header only, truncated", []byte{0x0A, 0x00, 0x00}, ErrShort},
		{"length beyond the cap", oversized, ErrTooLarge},
		{"length below the header", tooShortLength, ErrMalformed},
		{"body missing", Build(PktData, make([]byte, 40))[:20], ErrShort},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParsePacket(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// The cookie carries the token, so its parsing faces attacker input.
func TestTunnelCreateRejectsBadLengths(t *testing.T) {
	// Claims a 400-byte cookie but carries four bytes.
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[4:6], tunnelFieldPAACookie)

	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, 400)
	body = append(body, length...)
	body = append(body, 1, 2, 3, 4)

	if _, err := ParseTunnelCreate(body); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"pc-buero.lan", "Büro-PC", "", "日本語"} {
		if got := decodeUTF16(encodeUTF16(s)); got != s {
			t.Errorf("round trip of %q gave %q", s, got)
		}
	}
}

// Padding after a null must not leak into a hostname or a token.
func TestDecodeUTF16StopsAtNull(t *testing.T) {
	b := append(encodeUTF16("host"), 0, 0)
	b = append(b, encodeUTF16("junk")...)

	if got := decodeUTF16(b); got != "host" {
		t.Fatalf("decodeUTF16 = %q, want host", got)
	}
}

/* ----------------------------------------------------------------- fuzz --- */

// Everything here runs before the client is authorised, so it must never
// panic and never allocate without bound.
func FuzzParsePacket(f *testing.F) {
	f.Add(Build(PktData, []byte("hello")))
	f.Add(Build(PktHandshakeRequest, make([]byte, 6)))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, n, err := ParsePacket(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("claimed to consume %d of %d bytes", n, len(data))
		}
		if len(p.Body) > MaxPacket {
			t.Fatalf("body of %d bytes exceeds the cap", len(p.Body))
		}

		// Every body parser must survive whatever came through.
		ParseHandshakeRequest(p.Body)
		ParseTunnelCreate(p.Body)
		ParseTunnelAuth(p.Body)
		ParseChannelCreate(p.Body)
		ParseData(p.Body)
	})
}

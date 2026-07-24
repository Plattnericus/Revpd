package wol_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/wol"
)

func TestParseMACAcceptsCommonFormats(t *testing.T) {
	want := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	for _, in := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff",
		"aabbccddeeff",
		"  aa:bb:cc:dd:ee:ff  ",
	} {
		got, err := wol.ParseMAC(in)
		if err != nil {
			t.Errorf("ParseMAC(%q): %v", in, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ParseMAC(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseMACRejectsJunk(t *testing.T) {
	for _, in := range []string{"", "aa:bb:cc", "not-a-mac", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff"} {
		if _, err := wol.ParseMAC(in); !errors.Is(err, wol.ErrBadMAC) {
			t.Errorf("ParseMAC(%q) err = %v, want ErrBadMAC", in, err)
		}
	}
}

// The payload shape is fixed by the spec: six 0xFF bytes then the MAC sixteen times.
func TestMagicPacketShape(t *testing.T) {
	mac, _ := wol.ParseMAC("aa:bb:cc:dd:ee:ff")

	pkt, err := wol.MagicPacket(mac)
	if err != nil {
		t.Fatalf("MagicPacket: %v", err)
	}
	if len(pkt) != 102 {
		t.Fatalf("packet is %d bytes, want 102", len(pkt))
	}
	if !bytes.Equal(pkt[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("preamble = % x, want six 0xFF", pkt[:6])
	}
	for i := 0; i < 16; i++ {
		off := 6 + i*6
		if !bytes.Equal(pkt[off:off+6], mac) {
			t.Fatalf("MAC repetition %d = % x, want % x", i, pkt[off:off+6], mac)
		}
	}
}

// Send actually has to put those bytes on the wire.
func TestSendDeliversMagicPacket(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	mac, _ := wol.ParseMAC("00:11:22:33:44:55")

	if err := (wol.Sender{Repeat: 2}).Send(mac, "127.0.0.1", port); err != nil {
		t.Fatalf("Send: %v", err)
	}

	want, _ := wol.MagicPacket(mac)
	buf := make([]byte, 256)

	for i := 0; i < 2; i++ {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d not received: %v", i+1, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d does not match the expected magic packet", i+1)
		}
	}
}

func TestSendRejectsBadBroadcast(t *testing.T) {
	mac, _ := wol.ParseMAC("00:11:22:33:44:55")
	if err := (wol.Sender{}).Send(mac, "not-an-ip", 9); err == nil {
		t.Fatal("Send accepted a broadcast address that is not an IP")
	}
}

func TestWaitReadyReturnsWhenPortOpens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := wol.Prober{Interval: 50 * time.Millisecond, Settle: 50 * time.Millisecond}
	if err := p.WaitReady(ctx, ln.Addr().String()); err != nil {
		t.Fatalf("WaitReady on an open port: %v", err)
	}
}

// A machine that never wakes must surface as a timeout, not a hang.
func TestWaitReadyTimesOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	p := wol.Prober{Interval: 50 * time.Millisecond}

	start := time.Now()
	err := p.WaitReady(ctx, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WaitReady claimed a dead port came up")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("WaitReady overran its context by %v", time.Since(start))
	}
}

func TestAliveDistinguishesOpenFromClosed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	ctx := context.Background()
	if !wol.Alive(ctx, ln.Addr().String(), time.Second) {
		t.Fatal("Alive reported an open port as down")
	}
	if wol.Alive(ctx, "127.0.0.1:1", 200*time.Millisecond) {
		t.Fatal("Alive reported a closed port as up")
	}
}

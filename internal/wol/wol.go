// Package wol sends Wake-on-LAN magic packets and waits for the machine to answer.
package wol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

var ErrBadMAC = errors.New("not a MAC address")

// ParseMAC accepts the shapes people actually paste: aa:bb:cc:dd:ee:ff,
// AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff and bare hex.
func ParseMAC(s string) (net.HardwareAddr, error) {
	clean := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(s))
	if len(clean) != 12 {
		return nil, fmt.Errorf("%w: expected 12 hex digits, got %d", ErrBadMAC, len(clean))
	}

	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMAC, err)
	}
	return net.HardwareAddr(b), nil
}

// MagicPacket builds the 102-byte payload: six 0xFF bytes then the MAC sixteen times.
func MagicPacket(mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("%w: need 6 bytes, got %d", ErrBadMAC, len(mac))
	}

	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < 16; i++ {
		p = append(p, mac...)
	}
	return p, nil
}

type Sender struct {
	// Repeat guards against a single dropped UDP datagram. Cheap insurance.
	Repeat int
}

// Send fires the magic packet at the broadcast address.
func (s Sender) Send(mac net.HardwareAddr, broadcast string, port int) error {
	pkt, err := MagicPacket(mac)
	if err != nil {
		return err
	}

	addr := &net.UDPAddr{IP: net.ParseIP(broadcast), Port: port}
	if addr.IP == nil {
		return fmt.Errorf("broadcast address %q is not an IP", broadcast)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	n := s.Repeat
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		if _, err := conn.Write(pkt); err != nil {
			return fmt.Errorf("send magic packet: %w", err)
		}
		if i < n-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	slog.Info("magic packet sent", "mac", mac.String(), "broadcast", broadcast, "port", port, "repeat", n)
	return nil
}

// Prober polls a TCP port until the target starts answering.
type Prober struct {
	Interval time.Duration

	// Windows accepts the TCP handshake a moment before RDP is really ready.
	// Connecting into that gap gives the user a confusing protocol error, so
	// we wait this long after the first success.
	Settle time.Duration
}

// Alive reports whether the port is open right now.
func Alive(ctx context.Context, addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// WaitReady blocks until addr answers or the context is done.
func (p Prober) WaitReady(ctx context.Context, addr string) error {
	interval := p.Interval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		if Alive(ctx, addr, interval) {
			if p.Settle > 0 {
				select {
				case <-time.After(p.Settle):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}

		select {
		case <-t.C:
		case <-ctx.Done():
			return fmt.Errorf("target %s did not come up: %w", addr, ctx.Err())
		}
	}
}

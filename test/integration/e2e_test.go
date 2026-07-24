//go:build integration

// End-to-end proof that the whole chain holds together:
// MFA-issued grant -> Wake-on-LAN -> relay forwards -> target sees the bytes.
//
// Run with:  go test ./test/integration -tags=integration -v
package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/plattnericus/revpd/internal/wol"
)

/* -------------------------------------------------------------- harness --- */

// fakeWindows stands in for the RDP host: it records everything it receives.
//
// It can start asleep, which is the whole point of the product — the port
// stays shut until a magic packet arrives, exactly like a machine in S5.
type fakeWindows struct {
	tcpPort int
	bootFor time.Duration

	mu    sync.Mutex
	ln    net.Listener
	rx    []byte
	awake bool
}

func newFakeWindows(t *testing.T, asleep bool, bootFor time.Duration) *fakeWindows {
	t.Helper()

	// Grab a free port, then let go of it so the machine can be "off".
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	w := &fakeWindows{tcpPort: port, bootFor: bootFor}
	t.Cleanup(w.shutdown)

	if !asleep {
		if err := w.boot(); err != nil {
			t.Fatalf("boot fake target: %v", err)
		}
	}
	return w
}

// boot opens the RDP port, the way Windows does once it finishes starting.
func (w *fakeWindows) boot() error {
	w.mu.Lock()
	if w.awake {
		w.mu.Unlock()
		return nil
	}
	w.awake = true
	w.mu.Unlock()

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(w.tcpPort)))
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.ln = ln
	w.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 16*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						w.mu.Lock()
						w.rx = append(w.rx, buf[:n]...)
						w.mu.Unlock()
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return nil
}

// wake simulates the boot delay before RDP starts answering.
func (w *fakeWindows) wake() {
	go func() {
		time.Sleep(w.bootFor)
		w.boot()
	}()
}

func (w *fakeWindows) shutdown() {
	w.mu.Lock()
	ln := w.ln
	w.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

func (w *fakeWindows) received() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.rx...)
}

func (w *fakeWindows) port() int { return w.tcpPort }

// wolSink verifies the magic packet actually lands on the wire, and boots the
// fake machine when a valid one arrives.
type wolSink struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  [][]byte
}

func newWolSink(t *testing.T, onValidWake func()) *wolSink {
	t.Helper()

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &wolSink{conn: c}

	go func() {
		buf := make([]byte, 256)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)

			s.mu.Lock()
			s.got = append(s.got, pkt)
			s.mu.Unlock()

			// Only a well-formed packet wakes anything, same as real hardware.
			if len(pkt) == 102 && bytes.Equal(pkt[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) && onValidWake != nil {
				onValidWake()
			}
		}
	}()

	t.Cleanup(func() { c.Close() })
	return s
}

func (s *wolSink) packets() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.got...)
}

func (s *wolSink) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

type mockApprover struct {
	approve bool
	delay   time.Duration
	calls   int
	mu      sync.Mutex
}

func (m *mockApprover) Approve(ctx context.Context, _, _, _ string) (bool, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return m.approve, nil
}

func (m *mockApprover) called() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type env struct {
	db       *store.DB
	log      *audit.Log
	engine   *policy.Engine
	relay    *relay.Server
	windows  *fakeWindows
	wol      *wolSink
	approver *mockApprover
	user     *store.User
	target   *store.Target
	cfg      config.Config
}

func setup(t *testing.T, tweak func(*config.Config)) *env {
	return setupWith(t, false, 0, tweak)
}

// setupWith can start the target asleep, so the Wake-on-LAN path is exercised
// for real rather than assumed.
func setupWith(t *testing.T, asleep bool, bootFor time.Duration, tweak func(*config.Config)) *env {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	windows := newFakeWindows(t, asleep, bootFor)
	sink := newWolSink(t, windows.wake)

	cfg := config.Defaults()
	cfg.Grant.TTL = 2 * time.Minute
	cfg.Grant.ReuseWindow = 5 * time.Minute
	cfg.WoL.ProbeInterval = 50 * time.Millisecond
	cfg.WoL.ProbeSettle = 0
	cfg.WoL.Repeat = 1
	cfg.JIT.HoldTimeout = 3 * time.Second
	if tweak != nil {
		tweak(&cfg)
	}

	pwHash, err := crypto.HashPassword("hunter2-correct-horse")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	uid, err := db.CreateUser(ctx, store.User{
		Username: "felix", DisplayName: "Felix", PasswordHash: pwHash, Role: "user", RDPHint: "felix",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	tid, err := db.CreateTarget(ctx, store.Target{
		Name: "Büro-PC", IP: "127.0.0.1", RDPPort: windows.port(),
		MAC: "a8:a1:59:3c:d2:11", WoLBroadcast: "127.0.0.1", WoLPort: sink.port(),
		BootTimeoutS: 5,
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := db.GrantTargetAccess(ctx, uid, tid); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	user, _ := db.UserByID(ctx, uid)
	target, _ := db.TargetByID(ctx, tid)

	approver := &mockApprover{approve: true}
	engine := policy.New(db, log, cfg, approver)

	srv := relay.New(relay.Options{
		Listen:      "127.0.0.1:0",
		JITEnabled:  cfg.JIT.Enabled,
		PeekTimeout: 2 * time.Second,
		HoldTimeout: cfg.JIT.HoldTimeout,
		DialTimeout: 3 * time.Second,
		IdleTimeout: time.Minute,
		Tarpit:      0,
	}, engine, engine)

	rctx, cancel := context.WithCancel(ctx)
	go srv.Serve(rctx)
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("relay never bound")
	}
	t.Cleanup(cancel)

	return &env{db, log, engine, srv, windows, sink, approver, user, target, cfg}
}

// connectionRequest builds the first packet mstsc sends.
func connectionRequest(cookie string) []byte {
	variable := []byte{}
	if cookie != "" {
		variable = []byte("Cookie: mstshash=" + cookie + "\r\n")
	}
	variable = append(variable, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	body = append(body, variable...)

	pkt := make([]byte, 4, 4+len(body))
	pkt[0] = 3
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(body)))
	return append(pkt, body...)
}

// rdpConnect behaves like a client: send the CR, then some session traffic.
func rdpConnect(t *testing.T, addr, cookie string, payload []byte) ([]byte, error) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sent := append(connectionRequest(cookie), payload...)
	if _, err := conn.Write(sent); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	echoed := make([]byte, 0, len(sent))
	buf := make([]byte, 4096)
	for len(echoed) < len(sent) {
		n, err := conn.Read(buf)
		echoed = append(echoed, buf[:n]...)
		if err != nil {
			if len(echoed) == 0 {
				return nil, err
			}
			break
		}
	}
	return echoed, nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

/* ----------------------------------------------------------- the chain --- */

// The whole product in one test: a sleeping machine, MFA, Wake-on-LAN, and a
// byte-perfect RDP stream at the end of it.
func TestPortalFlowEndToEnd(t *testing.T) {
	e := setupWith(t, true, 400*time.Millisecond, nil) // target starts powered off
	ctx := context.Background()

	// The machine really is unreachable to begin with.
	if wol.Alive(ctx, e.target.Addr(), 300*time.Millisecond) {
		t.Fatal("target answered before it was woken")
	}

	// 1. MFA has passed; the portal unlocks the target.
	target, grantID, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if grantID == 0 {
		t.Fatal("unlock returned no grant")
	}

	// 2. A magic packet must actually have gone out, addressed to this MAC.
	waitFor(t, "the magic packet", func() bool { return len(e.wol.packets()) > 0 })

	mac, _ := wol.ParseMAC(target.MAC)
	want, _ := wol.MagicPacket(mac)
	if got := e.wol.packets()[0]; !bytes.Equal(got, want) {
		t.Fatal("magic packet on the wire does not match the target MAC")
	}

	// 3. The machine boots and starts answering on 3389.
	waitFor(t, "the target to finish booting", func() bool {
		return wol.Alive(ctx, e.target.Addr(), 200*time.Millisecond)
	})

	// 4. Now mstsc connects and the bytes must arrive untouched.
	payload := bytes.Repeat([]byte("rdp-session-traffic"), 512)
	echoed, err := rdpConnect(t, e.relay.Addr().String(), "felix", payload)
	if err != nil {
		t.Fatalf("rdp connect: %v", err)
	}

	expected := append(connectionRequest("felix"), payload...)
	if !bytes.Equal(echoed, expected) {
		t.Fatal("bytes echoed back through the relay differ from what was sent")
	}
	waitFor(t, "the target to receive everything", func() bool {
		return bytes.Equal(e.windows.received(), expected)
	})

	// 4. The session must be on record.
	waitFor(t, "the session to be logged", func() bool {
		entries, _ := e.log.List(ctx, audit.Query{Action: audit.ActionRelayOpen})
		return len(entries) == 1
	})

	// 5. And the audit chain must still verify.
	if brk, _, err := e.log.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("audit chain broken after a normal session: %v %v", brk, err)
	}
}

// The invariant: no grant, no bytes. Ever.
func TestConnectWithoutGrantReachesNothing(t *testing.T) {
	e := setup(t, nil)

	if _, err := rdpConnect(t, e.relay.Addr().String(), "felix", []byte("let me in")); err == nil {
		t.Fatal("relay answered a connection that had no grant")
	}
	if got := e.windows.received(); len(got) != 0 {
		t.Fatalf("target received %d bytes without a grant", len(got))
	}
}

// A grant belongs to one address. Someone else on the same gateway gets nothing.
func TestGrantIsBoundToSourceAddress(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("203.0.113.7")); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// The grant exists, but for a different address than the one connecting.
	d := e.engine.Authorize(ctx, net.ParseIP("198.51.100.99"))
	if d.Allow {
		t.Fatal("a grant issued for one address authorised another")
	}

	// The rightful address still works.
	if d := e.engine.Authorize(ctx, net.ParseIP("203.0.113.7")); !d.Allow {
		t.Fatalf("the address that passed MFA was refused: %s", d.Reason)
	}
}

func TestExpiredGrantIsRefused(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Grant.TTL = 300 * time.Millisecond })
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	time.Sleep(700 * time.Millisecond)

	if d := e.engine.Authorize(ctx, net.ParseIP("127.0.0.1")); d.Allow {
		t.Fatal("an expired grant still authorised a connection")
	}
	if _, err := rdpConnect(t, e.relay.Addr().String(), "felix", []byte("x")); err == nil {
		t.Fatal("relay forwarded on an expired grant")
	}
}

// Revoking access must bite immediately, even on an already-issued grant.
func TestRevokedAccessKillsAnExistingGrant(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if d := e.engine.Authorize(ctx, net.ParseIP("127.0.0.1")); !d.Allow {
		t.Fatal("grant did not work before revocation")
	}

	if err := e.db.RevokeTargetAccess(ctx, e.user.ID, e.target.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if d := e.engine.Authorize(ctx, net.ParseIP("127.0.0.1")); d.Allow {
		t.Fatal("connection allowed after access was revoked")
	}
}

// Locking an account must do the same.
func TestLockedAccountIsRefused(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := e.db.SetUserStatus(ctx, e.user.ID, "locked"); err != nil {
		t.Fatalf("lock user: %v", err)
	}

	if d := e.engine.Authorize(ctx, net.ParseIP("127.0.0.1")); d.Allow {
		t.Fatal("a locked account still got through")
	}
}

// A user must not be able to unlock a machine they were never given.
func TestUnlockRefusesForeignTarget(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()

	other, err := e.db.CreateTarget(ctx, store.Target{
		Name: "Fremder-PC", IP: "127.0.0.1", RDPPort: 3389, MAC: "00:11:22:33:44:55",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	if _, _, err := e.engine.Unlock(ctx, e.user, other, net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("unlocked a target the user has no access to")
	}
	if len(e.wol.packets()) != 0 {
		t.Fatal("a refused unlock still sent a magic packet")
	}
}

/* ----------------------------------------------------------------- JIT --- */

func TestJITApprovedForwards(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.JIT.Enabled = true })
	e.approver.approve = true

	payload := []byte("post-approval traffic")
	echoed, err := rdpConnect(t, e.relay.Addr().String(), "felix", payload)
	if err != nil {
		t.Fatalf("rdp connect: %v", err)
	}

	expected := append(connectionRequest("felix"), payload...)
	if !bytes.Equal(echoed, expected) {
		t.Fatal("JIT path altered the stream")
	}
	waitFor(t, "the target to receive the replayed handshake", func() bool {
		return bytes.Equal(e.windows.received(), expected)
	})
	if e.approver.called() != 1 {
		t.Fatalf("approver called %d times, want 1", e.approver.called())
	}
}

func TestJITDeniedReachesNothing(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.JIT.Enabled = true })
	e.approver.approve = false

	if _, err := rdpConnect(t, e.relay.Addr().String(), "felix", []byte("x")); err == nil {
		t.Fatal("relay forwarded despite the approval being declined")
	}
	if got := e.windows.received(); len(got) != 0 {
		t.Fatalf("target received %d bytes after a denial", len(got))
	}
}

// An unknown name must not be distinguishable from a denial.
func TestJITUnknownUserIsRefused(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.JIT.Enabled = true })

	if _, err := rdpConnect(t, e.relay.Addr().String(), "mallory", []byte("x")); err == nil {
		t.Fatal("relay forwarded for an unknown username")
	}
	if e.approver.called() != 0 {
		t.Fatal("an approval prompt was sent for an account that does not exist")
	}
	if len(e.windows.received()) != 0 {
		t.Fatal("target received bytes for an unknown username")
	}
}

// With JIT off, a connection without a grant must be dropped outright.
func TestJITDisabledDropsUnknownConnections(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.JIT.Enabled = false })

	if _, err := rdpConnect(t, e.relay.Addr().String(), "felix", []byte("x")); err == nil {
		t.Fatal("relay forwarded while JIT was disabled")
	}
	if e.approver.called() != 0 {
		t.Fatal("an approval was requested while JIT is disabled")
	}
}

// A grant beats JIT: an already-authorised address must never trigger a push.
func TestExistingGrantSkipsApproval(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.JIT.Enabled = true })
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := rdpConnect(t, e.relay.Addr().String(), "felix", []byte("hello")); err != nil {
		t.Fatalf("rdp connect: %v", err)
	}
	if e.approver.called() != 0 {
		t.Fatal("a push was sent even though a valid grant existed")
	}
}

/* -------------------------------------------------------------- extras --- */

// Ten browser tabs must not mean ten magic packets and ten prober goroutines.
func TestConcurrentUnlocksSendOneMagicPacket(t *testing.T) {
	e := setupWith(t, true, 300*time.Millisecond, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1"))
		}()
	}
	wg.Wait()

	waitFor(t, "the magic packet", func() bool { return len(e.wol.packets()) > 0 })
	time.Sleep(600 * time.Millisecond)

	// Repeat is 1 in this config, so one wake means exactly one datagram.
	if n := len(e.wol.packets()); n != 1 {
		t.Fatalf("%d magic packets for one target, want 1 — wake was not deduplicated", n)
	}
}

// An already-running machine must not be woken again on every unlock.
func TestUnlockDoesNotWakeAnAwakeTarget(t *testing.T) {
	e := setup(t, nil) // target is up from the start
	ctx := context.Background()

	if _, _, err := e.engine.Unlock(ctx, e.user, e.target.ID, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	if n := len(e.wol.packets()); n != 0 {
		t.Fatalf("sent %d magic packets to a machine that was already up", n)
	}
}

func TestPasswordVerificationIsWiredUp(t *testing.T) {
	e := setup(t, nil)

	if err := crypto.VerifyPassword("hunter2-correct-horse", e.user.PasswordHash); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if err := crypto.VerifyPassword("wrong", e.user.PasswordHash); !errors.Is(err, crypto.ErrMismatch) {
		t.Fatalf("wrong password err = %v, want ErrMismatch", err)
	}
}

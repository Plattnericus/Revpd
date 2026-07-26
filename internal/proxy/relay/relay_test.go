package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/proxy/x224"
)

// --- test doubles -----------------------------------------------------------

type fakePolicy struct {
	allow   bool
	backend string

	jitAllow bool
	jitDelay time.Duration

	validToken string

	mu       sync.Mutex
	sawHint  string
	sawToken string
	reviewed int
}

func (p *fakePolicy) Authorize(context.Context, net.IP) relay.Decision {
	if !p.allow {
		return relay.Decision{Reason: "no grant for this address"}
	}
	return relay.Decision{Allow: true, Backend: p.backend, GrantID: 1, TargetID: 1}
}

func (p *fakePolicy) Review(ctx context.Context, _ net.IP, cr *x224.ConnectionRequest) relay.Decision {
	p.mu.Lock()
	p.sawHint = cr.Cookie
	p.reviewed++
	p.mu.Unlock()

	if p.jitDelay > 0 {
		select {
		case <-time.After(p.jitDelay):
		case <-ctx.Done():
			return relay.Decision{Reason: "approval timed out"}
		}
	}
	if !p.jitAllow {
		return relay.Decision{Reason: "denied"}
	}
	return relay.Decision{Allow: true, Backend: p.backend, GrantID: 2, TargetID: 1}
}

func (p *fakePolicy) AuthorizeToken(_ context.Context, _ net.IP, token string) relay.Decision {
	p.mu.Lock()
	p.sawToken = token
	p.mu.Unlock()

	if token != p.validToken || p.validToken == "" {
		return relay.Decision{Reason: "redirect token is not valid"}
	}
	return relay.Decision{Allow: true, Backend: p.backend, GrantID: 3, TargetID: 1}
}

func (p *fakePolicy) hint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sawHint
}

// fakeLogin stands in for the RDP-native login.
type fakeLogin struct {
	mu    sync.Mutex
	calls int
	err   error
	sawCR []byte
}

func (l *fakeLogin) Run(_ context.Context, conn net.Conn, cr *x224.ConnectionRequest, _ net.IP) (string, error) {
	l.mu.Lock()
	l.calls++
	l.sawCR = append([]byte(nil), cr.Raw...)
	l.mu.Unlock()

	// The real one speaks RDP here. All the relay cares about is that the
	// connection is finished when this returns.
	conn.Close()
	return "felix", l.err
}

func (l *fakeLogin) called() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

type fakeRecorder struct {
	mu        sync.Mutex
	opened    int
	closed    int
	rejected  int
	lastWhy   string
	lastHint  string
	bytesIn   int64
	bytesOut  int64
	sessionID atomic.Int64
}

func (r *fakeRecorder) Opened(context.Context, relay.Decision, net.IP) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened++
	return r.sessionID.Add(1)
}

func (r *fakeRecorder) Closed(_ context.Context, _ int64, in, out int64, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	r.bytesIn, r.bytesOut, r.lastWhy = in, out, reason
}

func (r *fakeRecorder) Rejected(_ context.Context, _ net.IP, reason, hint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected++
	r.lastWhy, r.lastHint = reason, hint
}

func (r *fakeRecorder) counts() (opened, closed, rejected int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened, r.closed, r.rejected
}

// --- harness ----------------------------------------------------------------

// echoBackend stands in for a Windows box: it records what arrives and
// echoes it back, so the test can prove the stream survived untouched.
type echoBackend struct {
	ln       net.Listener
	mu       sync.Mutex
	received []byte
	done     chan struct{}
}

func newEchoBackend(t *testing.T) *echoBackend {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	b := &echoBackend{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						b.mu.Lock()
						b.received = append(b.received, buf[:n]...)
						b.mu.Unlock()
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *echoBackend) addr() string { return b.ln.Addr().String() }

func (b *echoBackend) got() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.received...)
}

func startRelay(t *testing.T, opts relay.Options, pol relay.Policy, rec relay.Recorder) *relay.Server {
	t.Helper()

	opts.Listen = "127.0.0.1:0"
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 2 * time.Second
	}
	if opts.PeekTimeout == 0 {
		opts.PeekTimeout = 2 * time.Second
	}
	if opts.HoldTimeout == 0 {
		opts.HoldTimeout = 2 * time.Second
	}

	s := relay.New(opts, pol, rec)
	ctx, cancel := context.WithCancel(context.Background())

	ready := make(chan struct{})
	go func() {
		close(ready)
		s.Serve(ctx)
	}()
	<-ready

	// Serve binds asynchronously; wait for the address to appear.
	for i := 0; i < 200 && s.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("relay never bound a port")
	}

	t.Cleanup(cancel)
	return s
}

func buildCR(cookie string) []byte {
	variable := []byte{}
	if cookie != "" {
		variable = []byte("Cookie: mstshash=" + cookie + "\r\n")
	}
	return wrapCR(variable)
}

// buildRoutingCR is what a client sends after a Server Redirection.
func buildRoutingCR(token string) []byte {
	return wrapCR([]byte("Cookie: msts=" + token + "\r\n"))
}

func wrapCR(variable []byte) []byte {
	variable = append(variable, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	body = append(body, variable...)

	total := 4 + len(body)
	pkt := make([]byte, 4, total)
	pkt[0] = 3
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	return append(pkt, body...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- the invariant ----------------------------------------------------------

// The rule the whole product rests on: no grant, no forwarding.
func TestNoGrantIsNeverForwarded(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, backend: backend.addr()}
	rec := &fakeRecorder{}

	s := startRelay(t, relay.Options{JITEnabled: false, Tarpit: 0}, pol, rec)

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	conn.Write(buildCR("felix"))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("relay returned data for an unauthorised connection")
	}

	if got := backend.got(); len(got) != 0 {
		t.Fatalf("backend received %d bytes without a grant", len(got))
	}

	opened, _, rejected := rec.counts()
	if opened != 0 {
		t.Fatalf("recorded %d opened sessions, want 0", opened)
	}
	if rejected != 1 {
		t.Fatalf("recorded %d rejections, want 1", rejected)
	}
}

// A client returning from a redirection carries a token; a valid one is the
// normal way through.
func TestValidRoutingTokenIsForwarded(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, backend: backend.addr(), validToken: "goodtoken"}

	s := startRelay(t, relay.Options{}, pol, &fakeRecorder{})

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sent := buildRoutingCR("goodtoken")
	conn.Write(sent)

	waitFor(t, "the backend to receive the handshake", func() bool {
		return bytes.Equal(backend.got(), sent)
	})
}

// An unknown token must be refused outright. Sending such a client into the
// login would loop it: redirect, reconnect, redirect, forever.
func TestInvalidRoutingTokenIsRefusedNotSentToLogin(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, backend: backend.addr(), validToken: "goodtoken"}
	login := &fakeLogin{}
	rec := &fakeRecorder{}

	s := startRelay(t, relay.Options{Login: login, Tarpit: 0}, pol, rec)

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildRoutingCR("staletoken"))
	time.Sleep(400 * time.Millisecond)

	if login.called() != 0 {
		t.Fatal("a stale token was sent into the login instead of being refused")
	}
	if len(backend.got()) != 0 {
		t.Fatalf("backend received %d bytes for an invalid token", len(backend.got()))
	}
	if _, _, rejected := rec.counts(); rejected != 1 {
		t.Fatalf("recorded %d rejections, want 1", rejected)
	}
}

// With no grant and no token, the login takes the connection over.
func TestNoGrantGoesToLogin(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, backend: backend.addr()}
	login := &fakeLogin{}

	s := startRelay(t, relay.Options{Login: login}, pol, &fakeRecorder{})

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()

	sent := buildCR("felix")
	conn.Write(sent)
	time.Sleep(400 * time.Millisecond)

	if login.called() != 1 {
		t.Fatalf("login called %d times, want 1", login.called())
	}
	if !bytes.Equal(login.sawCR, sent) {
		t.Fatal("login received a different connection request than the client sent")
	}
	if len(backend.got()) != 0 {
		t.Fatal("backend received bytes before the login finished")
	}
}

// A valid grant must skip the login entirely.
func TestExistingGrantSkipsLogin(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: true, backend: backend.addr()}
	login := &fakeLogin{}

	s := startRelay(t, relay.Options{Login: login}, pol, &fakeRecorder{})

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildCR("felix"))
	time.Sleep(300 * time.Millisecond)

	if login.called() != 0 {
		t.Fatal("login ran even though a valid grant existed")
	}
}

// The headline property: what the client sends is exactly what the target gets.
func TestStreamIsByteIdentical(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: true, backend: backend.addr()}

	s := startRelay(t, relay.Options{}, pol, &fakeRecorder{})

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// A connection request followed by traffic that looks nothing like RDP --
	// the relay must not care either way.
	sent := buildCR("felix")
	blob := make([]byte, 256*1024)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("random payload: %v", err)
	}
	sent = append(sent, blob...)

	var wg sync.WaitGroup
	wg.Add(1)
	echoed := make([]byte, 0, len(sent))
	var readErr error

	go func() {
		defer wg.Done()
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 32*1024)
		for len(echoed) < len(sent) {
			n, err := conn.Read(buf)
			echoed = append(echoed, buf[:n]...)
			if err != nil {
				readErr = err
				return
			}
		}
	}()

	if _, err := conn.Write(sent); err != nil {
		t.Fatalf("write: %v", err)
	}
	wg.Wait()

	if readErr != nil && len(echoed) < len(sent) {
		t.Fatalf("read back only %d of %d bytes: %v", len(echoed), len(sent), readErr)
	}
	if !bytes.Equal(echoed, sent) {
		t.Fatal("bytes returned through the relay differ from what was sent")
	}
	if got := backend.got(); !bytes.Equal(got, sent) {
		t.Fatalf("backend saw %d bytes, client sent %d -- stream was altered", len(got), len(sent))
	}
}

// JIT peeks the first packet, so it must replay it verbatim or NLA breaks.
func TestJITReplaysFirstPacketVerbatim(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, jitAllow: true, backend: backend.addr()}

	s := startRelay(t, relay.Options{JITEnabled: true}, pol, &fakeRecorder{})

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	cr := buildCR("felix")
	tail := []byte("post-handshake traffic")
	conn.Write(cr)
	time.Sleep(200 * time.Millisecond)
	conn.Write(tail)

	want := append(append([]byte{}, cr...), tail...)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(backend.got()) >= len(want) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := backend.got(); !bytes.Equal(got, want) {
		t.Fatalf("backend received %d bytes, want %d identical -- replay altered the handshake", len(got), len(want))
	}
	if pol.hint() != "felix" {
		t.Fatalf("policy saw hint %q, want felix", pol.hint())
	}
}

func TestJITDeniedIsNotForwarded(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, jitAllow: false, backend: backend.addr()}
	rec := &fakeRecorder{}

	s := startRelay(t, relay.Options{JITEnabled: true}, pol, rec)

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildCR("felix"))
	time.Sleep(500 * time.Millisecond)

	if got := backend.got(); len(got) != 0 {
		t.Fatalf("backend received %d bytes after a denial", len(got))
	}
	if _, _, rejected := rec.counts(); rejected != 1 {
		t.Fatalf("recorded %d rejections, want 1", rejected)
	}
	if rec.lastHint != "felix" {
		t.Fatalf("rejection recorded hint %q, want felix", rec.lastHint)
	}
}

// An approval that never arrives must release the connection, not wedge it.
func TestJITHoldTimeoutReleases(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: false, jitAllow: true, jitDelay: 3 * time.Second, backend: backend.addr()}

	s := startRelay(t, relay.Options{
		JITEnabled:  true,
		HoldTimeout: 400 * time.Millisecond,
	}, pol, &fakeRecorder{})

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildCR("felix"))

	start := time.Now()
	for time.Since(start) < 3*time.Second && s.Active() > 0 {
		time.Sleep(20 * time.Millisecond)
	}

	if s.Active() != 0 {
		t.Fatal("connection was still held after the timeout expired")
	}
	if len(backend.got()) != 0 {
		t.Fatal("backend received data despite the approval timing out")
	}
}

// A client that connects and says nothing must not pin a goroutine.
func TestPeekTimeoutOnSilentClient(t *testing.T) {
	pol := &fakePolicy{allow: false, jitAllow: true, backend: "127.0.0.1:1"}

	s := startRelay(t, relay.Options{
		JITEnabled:  true,
		PeekTimeout: 300 * time.Millisecond,
	}, pol, &fakeRecorder{})

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	// Say nothing at all.

	start := time.Now()
	for time.Since(start) < 3*time.Second && s.Active() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Active() != 0 {
		t.Fatal("silent client held a slot past the peek timeout")
	}
}

func TestPerIPConnectionCap(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: true, backend: backend.addr()}
	rec := &fakeRecorder{}

	s := startRelay(t, relay.Options{MaxConnsPerIP: 2, Tarpit: 0}, pol, rec)

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", s.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
		c.Write(buildCR("felix"))
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	opened, _, rejected := rec.counts()
	if opened != 2 {
		t.Fatalf("opened %d sessions, want 2 (the cap)", opened)
	}
	if rejected != 2 {
		t.Fatalf("rejected %d connections, want 2", rejected)
	}
}

// Fifty sessions in and out must not leak goroutines.
func TestNoGoroutineLeakUnderLoad(t *testing.T) {
	backend := newEchoBackend(t)
	pol := &fakePolicy{allow: true, backend: backend.addr()}

	s := startRelay(t, relay.Options{MaxConnsPerIP: 0}, pol, &fakeRecorder{})

	runtime.GC()
	before := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			c, err := net.Dial("tcp", s.Addr().String())
			if err != nil {
				return
			}
			c.Write(buildCR("felix"))

			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadFull(c, make([]byte, 4))
			c.Close()
		}()
	}
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.Active() > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if s.Active() != 0 {
		t.Fatalf("%d connections still active after all clients closed", s.Active())
	}

	time.Sleep(300 * time.Millisecond)
	runtime.GC()

	// Allow some slack for the runtime's own workers.
	if after := runtime.NumGoroutine(); after > before+15 {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
}

// If the target is down, the client gets nothing and no session is recorded.
func TestUnreachableBackendIsNotRecordedAsSession(t *testing.T) {
	pol := &fakePolicy{allow: true, backend: "127.0.0.1:1"} // nothing listens here
	rec := &fakeRecorder{}

	s := startRelay(t, relay.Options{DialTimeout: 500 * time.Millisecond}, pol, rec)

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildCR("felix"))
	time.Sleep(1 * time.Second)

	opened, _, rejected := rec.counts()
	if opened != 0 {
		t.Fatalf("recorded %d sessions for an unreachable target", opened)
	}
	if rejected != 1 {
		t.Fatalf("recorded %d rejections, want 1", rejected)
	}
}

// A policy bug that allows without naming a backend must fail closed.
func TestAllowWithoutBackendFailsClosed(t *testing.T) {
	rec := &fakeRecorder{}
	pol := &fakePolicy{allow: true, backend: ""}

	s := startRelay(t, relay.Options{}, pol, rec)

	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	conn.Write(buildCR("felix"))
	time.Sleep(500 * time.Millisecond)

	if opened, _, _ := rec.counts(); opened != 0 {
		t.Fatalf("opened %d sessions with an empty backend", opened)
	}
}

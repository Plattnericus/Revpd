// Package relay is the RDP data plane: a transparent TCP proxy on :3389.
//
// It never decodes the RDP stream. The only bytes it looks at are the first
// X.224 connection request, and only to read the mstshash hint. Everything
// else is copied through untouched, which is why NLA, CredSSP, clipboard,
// drive redirection and multi-monitor all keep working end to end.
//
// The one invariant, from CLAUDE.md section 6:
//
//	No connection is ever forwarded without a valid grant or an approved
//	JIT request. Any change here must preserve that.
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plattnericus/revpd/internal/proxy/x224"
)

// Decision is what the policy engine says about an inbound connection.
type Decision struct {
	Allow bool

	// Backend is the "host:port" to forward to. Only read when Allow is true.
	Backend string

	// GrantID and TargetID go into the session record for the activity page.
	GrantID  int64
	TargetID int64

	// Reason is logged and audited on refusal. It is never sent to the client:
	// a scanner learns nothing from a silent drop.
	Reason string
}

// Policy decides whether a connection may proceed.
//
// Authorize runs first and covers the portal path: an existing grant for this
// source IP. It gets no packet contents at all.
//
// When Authorize declines and JIT is on, the relay reads the connection
// request and calls Review, which may block for as long as the hold timeout
// while it waits for a push approval.
type Policy interface {
	Authorize(ctx context.Context, srcIP net.IP) Decision
	Review(ctx context.Context, srcIP net.IP, cr *x224.ConnectionRequest) Decision

	// AuthorizeToken resolves the routing token a client carries when it comes
	// back after a Server Redirection. This is the normal path: the user has
	// just passed MFA inside their RDP client and is being handed on.
	AuthorizeToken(ctx context.Context, srcIP net.IP, token string) Decision
}

// LoginHandler runs the RDP-native login on a connection that has no grant.
//
// It takes the connection over completely — it terminates TLS and speaks RDP
// itself — and the connection is finished when Run returns. The client comes
// back as a fresh connection carrying a routing token.
type LoginHandler interface {
	Run(ctx context.Context, conn net.Conn, cr *x224.ConnectionRequest, srcIP net.IP) (string, error)
}

// Recorder receives session lifecycle events for the audit log and live view.
type Recorder interface {
	Opened(ctx context.Context, d Decision, srcIP net.IP) (sessionID int64)
	Closed(ctx context.Context, sessionID int64, in, out int64, reason string)
	Rejected(ctx context.Context, srcIP net.IP, reason string, hint string)
}

type Options struct {
	Listen        string
	JITEnabled    bool
	PeekTimeout   time.Duration
	HoldTimeout   time.Duration
	DialTimeout   time.Duration
	IdleTimeout   time.Duration
	Tarpit        time.Duration
	MaxConnsPerIP int

	// Login handles connections with no grant by asking for credentials
	// inside the RDP client itself. Nil disables it, which leaves the portal
	// as the only way in.
	Login LoginHandler
}

type Server struct {
	opts Options
	pol  Policy
	rec  Recorder

	ln net.Listener
	wg sync.WaitGroup

	mu      sync.Mutex
	perIP   map[string]int
	active  atomic.Int64
	stopped atomic.Bool
}

func New(opts Options, pol Policy, rec Recorder) *Server {
	return &Server{opts: opts, pol: pol, rec: rec, perIP: map[string]int{}}
}

func (s *Server) Serve(ctx context.Context) error {
	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "tcp", s.opts.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.opts.Listen, err)
	}
	s.ln = ln

	slog.Info("relay listening", "addr", ln.Addr().String(), "jit", s.opts.JITEnabled)

	// Unblock Accept on shutdown.
	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.stopped.Load() {
				break
			}
			// A single bad accept is not worth tearing the listener down.
			slog.Warn("accept failed", "err", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}

	s.wg.Wait()
	slog.Info("relay stopped")
	return nil
}

// Addr is useful in tests that bind to port 0.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *Server) Active() int64 { return s.active.Load() }

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	srcIP := ipOf(client.RemoteAddr())
	if srcIP == nil {
		return
	}

	if !s.acquire(srcIP.String()) {
		s.rec.Rejected(ctx, srcIP, "too many concurrent connections from this address", "")
		s.tarpit(ctx, client)
		return
	}
	defer s.release(srcIP.String())

	s.active.Add(1)
	defer s.active.Add(-1)

	// The first packet tells us which of the three paths this is. It is read
	// but never altered: it gets replayed to the backend byte for byte.
	cr, br, err := s.peek(client)
	if err != nil {
		s.rec.Rejected(ctx, srcIP, "malformed connection request: "+err.Error(), "")
		s.tarpit(ctx, client)
		return
	}

	// Whatever we peeked has to be replayed to the backend verbatim.
	replay := cr.Raw

	// Reads from the client go through the buffered reader, which may already
	// hold bytes that arrived alongside the handshake. Reading from the bare
	// socket instead would silently drop them mid-session.
	var clientSrc io.Reader = br

	var d Decision
	switch {
	case cr.RoutingToken != "":
		// The client is coming back after a redirection. It just passed MFA.
		d = s.pol.AuthorizeToken(ctx, srcIP, cr.RoutingToken)
	default:
		d = s.pol.Authorize(ctx, srcIP)
	}

	if !d.Allow {
		switch {
		// A token that did not check out is final: sending such a client into
		// the login would loop it forever.
		case cr.RoutingToken != "":
			s.rec.Rejected(ctx, srcIP, d.Reason, cr.Cookie)
			s.tarpit(ctx, client)
			return

		case s.opts.Login != nil:
			// A well-behaved client waits for our answer before sending more.
			// Anything buffered here means it did not, so the login's TLS
			// handshake would start on desynchronised data.
			if br.Buffered() > 0 {
				s.rec.Rejected(ctx, srcIP, "client sent data before the server answered", cr.Cookie)
				s.tarpit(ctx, client)
				return
			}

			user, err := s.opts.Login.Run(ctx, client, cr, srcIP)
			if err != nil {
				s.rec.Rejected(ctx, srcIP, "login failed", cr.Cookie)
				return
			}
			slog.Info("login completed, client will reconnect", "src", srcIP, "user", user)
			return

		case s.opts.JITEnabled:
			// Review can block for the whole hold timeout while a push is pending.
			hold, cancel := context.WithTimeout(ctx, s.opts.HoldTimeout)
			d = s.pol.Review(hold, srcIP, cr)
			cancel()

			if !d.Allow {
				s.rec.Rejected(ctx, srcIP, d.Reason, cr.Cookie)
				s.tarpit(ctx, client)
				return
			}

		default:
			s.rec.Rejected(ctx, srcIP, d.Reason, cr.Cookie)
			s.tarpit(ctx, client)
			return
		}
	}

	// Belt and braces: never dial on an empty backend.
	if d.Backend == "" {
		s.rec.Rejected(ctx, srcIP, "policy allowed the connection but named no backend", "")
		return
	}

	dialer := net.Dialer{Timeout: s.opts.DialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", d.Backend)
	if err != nil {
		slog.Warn("backend unreachable", "backend", d.Backend, "src", srcIP, "err", err)
		s.rec.Rejected(ctx, srcIP, "backend unreachable: "+err.Error(), "")
		return
	}
	defer backend.Close()

	tuneTCP(client)
	tuneTCP(backend)

	// Replay the peeked packet first or the handshake never completes.
	if len(replay) > 0 {
		if _, err := backend.Write(replay); err != nil {
			slog.Warn("replay to backend failed", "backend", d.Backend, "err", err)
			return
		}
	}

	sessionID := s.rec.Opened(ctx, d, srcIP)
	slog.Info("relay open", "src", srcIP, "backend", d.Backend, "session", sessionID)

	in, out, reason := s.pump(ctx, client, clientSrc, backend)

	s.rec.Closed(ctx, sessionID, in, out, reason)
	slog.Info("relay close", "session", sessionID, "in", in, "out", out, "reason", reason)
}

// peek reads the connection request under its own deadline so a client that
// connects and then goes quiet cannot pin a goroutine.
//
// The reader comes back with it: TCP does not preserve write boundaries, so
// the client's next bytes often land in the same segment as the handshake and
// end up buffered here. Whoever forwards the stream must keep reading from
// this reader, not from the socket.
func (s *Server) peek(client net.Conn) (*x224.ConnectionRequest, *bufio.Reader, error) {
	if err := client.SetReadDeadline(time.Now().Add(s.opts.PeekTimeout)); err != nil {
		return nil, nil, err
	}
	defer client.SetReadDeadline(time.Time{})

	// A fixed-size bufio reader is its own bound: a hostile client cannot make
	// us buffer more than this, and x224.Read rejects anything over MaxCRSize.
	br := bufio.NewReaderSize(client, x224.MaxCRSize)

	cr, err := x224.Read(br)
	if err != nil {
		return nil, nil, err
	}
	return cr, br, nil
}

// pump copies in both directions until one side hangs up.
//
// clientSrc is where client bytes are read from; it is the socket on the
// portal path and the buffered reader on the JIT path.
func (s *Server) pump(ctx context.Context, client net.Conn, clientSrc io.Reader, backend net.Conn) (in, out int64, reason string) {
	var (
		wg    sync.WaitGroup
		once  sync.Once
		cause string
	)

	finish := func(why string) {
		once.Do(func() {
			cause = why
			client.Close()
			backend.Close()
		})
	}

	// Closing both ends is what actually unblocks the two copies.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			finish("gateway shutting down")
		case <-stop:
		}
	}()

	copy := func(dst io.Writer, src io.Reader, deadline net.Conn, n *int64, why string) {
		defer wg.Done()

		c, err := copyIdle(dst, src, deadline, s.opts.IdleTimeout)
		atomic.StoreInt64(n, c)

		if errors.Is(err, errIdle) {
			finish("idle timeout")
			return
		}
		finish(why)
	}

	wg.Add(2)
	go copy(backend, clientSrc, client, &in, "client disconnected")
	go copy(client, backend, backend, &out, "target disconnected")
	wg.Wait()

	return atomic.LoadInt64(&in), atomic.LoadInt64(&out), cause
}

var errIdle = errors.New("idle")

// copyIdle is io.Copy with an inactivity deadline, so a half-dead RDP session
// eventually frees its file descriptors instead of lingering for hours.
//
// deadline is the underlying socket; src may be a reader wrapped around it.
func copyIdle(dst io.Writer, src io.Reader, deadline net.Conn, idle time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for {
		if idle > 0 {
			if err := deadline.SetReadDeadline(time.Now().Add(idle)); err != nil {
				return total, err
			}
		}

		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return total, errIdle
			}
			return total, err
		}
	}
}

// tarpit holds a rejected connection open for a moment before dropping it.
//
// Scanners hammering 3389 pay for the wait; a legitimate client never lands
// here. We say nothing on the wire, so a prober cannot tell an unknown user
// from a denied one.
func (s *Server) tarpit(ctx context.Context, conn net.Conn) {
	if s.opts.Tarpit <= 0 {
		return
	}
	select {
	case <-time.After(s.opts.Tarpit):
	case <-ctx.Done():
	}
}

func (s *Server) acquire(ip string) bool {
	if s.opts.MaxConnsPerIP <= 0 {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.perIP[ip] >= s.opts.MaxConnsPerIP {
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	if s.opts.MaxConnsPerIP <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.perIP[ip] <= 1 {
		delete(s.perIP, ip) // do not leak a map entry per scanner
		return
	}
	s.perIP[ip]--
}

func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	// RDP is latency-sensitive and sends small packets; Nagle hurts here.
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
}

func ipOf(addr net.Addr) net.IP {
	if ta, ok := addr.(*net.TCPAddr); ok {
		return ta.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

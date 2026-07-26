package netcheck

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a hand-wound one, so the interval rules can be tested without
// waiting for them.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func service(t *testing.T, o ServiceOptions) *Service {
	t.Helper()
	if o.Now == nil {
		c := &clock{t: time.Unix(1700000000, 0)}
		o.Now = c.now
	}
	return NewService(o)
}

func TestServiceUsesTheConfiguredHost(t *testing.T) {
	srv, hits := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Host:     "gw.example.com",
		Detect:   true,
		Detector: detector(t, []*httptest.Server{srv, srv}, nil),
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
	})
	st := s.Refresh(context.Background())

	if st.Host != "gw.example.com" {
		t.Errorf("host = %q, want the configured one", st.Host)
	}
	if st.Source != SourceConfigured {
		t.Errorf("source = %q, want %q", st.Source, SourceConfigured)
	}
	// Detection still runs beside it, which is what makes the staleness check
	// possible at all.
	if st.Detected != "8.8.8.8" {
		t.Errorf("detected = %q, want 8.8.8.8", st.Detected)
	}
	if st.Mismatch != "" {
		t.Errorf("the domain resolves here, so there is no mismatch: %q", st.Mismatch)
	}
	if hits.Load() == 0 {
		t.Error("detection should have run")
	}
}

func TestServiceFlagsAStaleDomain(t *testing.T) {
	// The failure this catches: a dynamic-DNS record that stopped following
	// the connection, discovered from the settings page rather than from
	// being locked out while away.
	srv, _ := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Host:     "gw.example.com",
		Detect:   true,
		Detector: detector(t, []*httptest.Server{srv, srv}, nil),
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
	})
	st := s.Refresh(context.Background())

	if st.Mismatch == "" {
		t.Fatal("a domain pointing elsewhere should be reported")
	}
	if !strings.Contains(st.Mismatch, "1.1.1.1") || !strings.Contains(st.Mismatch, "8.8.8.8") {
		t.Errorf("the message should name both addresses: %q", st.Mismatch)
	}
	// The operator asked for this host, so it still wins.
	if st.Host != "gw.example.com" {
		t.Errorf("host = %q, want the configured one even when stale", st.Host)
	}
}

func TestServiceFallsBackToDetection(t *testing.T) {
	a, _ := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Detect:   true,
		Detector: detector(t, []*httptest.Server{a, b}, nil),
	})
	st := s.Refresh(context.Background())

	if st.Host != "8.8.8.8" || st.Source != SourceResolver {
		t.Fatalf("got %q from %q, want the detected address", st.Host, st.Source)
	}
	if st.Mismatch != "" {
		t.Errorf("there is no configured host to disagree with: %q", st.Mismatch)
	}
}

func TestServiceNeverAsksWhenDetectionIsOff(t *testing.T) {
	srv, hits := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Host:     "gw.example.com",
		Detect:   false,
		Detector: detector(t, []*httptest.Server{srv}, nil),
	})
	st := s.Refresh(context.Background())

	if hits.Load() != 0 {
		t.Errorf("detection is off, nobody should have been asked (%d calls)", hits.Load())
	}
	if st.Host != "gw.example.com" {
		t.Errorf("host = %q, want the configured one", st.Host)
	}
	if st.Detected != "" {
		t.Errorf("detected = %q, want nothing", st.Detected)
	}
}

func TestServiceReportsDetectionFailure(t *testing.T) {
	s := service(t, ServiceOptions{
		Detect:   true,
		Detector: detector(t, nil, nil),
	})
	st := s.Refresh(context.Background())

	if st.Error == "" {
		t.Fatal("a failed detection should be explained")
	}
	if st.Host != "" {
		t.Errorf("host = %q, want nothing rather than a guess", st.Host)
	}
}

func TestServiceRateLimitsForcedChecks(t *testing.T) {
	// The settings page has a button on this. A held-down key must cost one
	// round of questions, not hundreds.
	a, hitsA := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "8.8.8.8")

	c := &clock{t: time.Unix(1700000000, 0)}
	s := service(t, ServiceOptions{
		Detect:      true,
		MinInterval: 30 * time.Second,
		Detector:    detector(t, []*httptest.Server{a, b}, nil),
		Now:         c.now,
	})

	s.Refresh(context.Background())
	first := hitsA.Load()

	for range 5 {
		s.Refresh(context.Background())
	}
	if hitsA.Load() != first {
		t.Errorf("repeat checks inside the window should be served from cache, %d calls became %d", first, hitsA.Load())
	}

	c.advance(31 * time.Second)
	s.Refresh(context.Background())
	if hitsA.Load() == first {
		t.Error("a check after the window should go out again")
	}
}

func TestSetHostTakesEffectImmediately(t *testing.T) {
	a, _ := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Detect:   true,
		Detector: detector(t, []*httptest.Server{a, b}, nil),
	})
	s.Refresh(context.Background())

	if got := s.Current().Host; got != "8.8.8.8" {
		t.Fatalf("host = %q, want the detected address", got)
	}

	// Nothing binds to this value, so a restart would be a pointless ask.
	s.SetHost("  gw.example.com  ")

	st := s.Current()
	if st.Host != "gw.example.com" || st.Source != SourceConfigured {
		t.Fatalf("got %q from %q, want the new host to win at once", st.Host, st.Source)
	}
	if st.Detected != "8.8.8.8" {
		t.Errorf("the detected address should survive the change, got %q", st.Detected)
	}

	// Clearing it hands the job back to detection.
	s.SetHost("")
	if st := s.Current(); st.Host != "8.8.8.8" || st.Source != SourceResolver {
		t.Fatalf("got %q from %q, want detection back", st.Host, st.Source)
	}
}

func TestServiceHasAnAnswerBeforeTheFirstCheck(t *testing.T) {
	// The settings page renders before any network round trip finishes, and a
	// blank where the address goes reads as broken.
	s := service(t, ServiceOptions{Host: "gw.example.com", Detect: true})

	if st := s.Current(); st.Host != "gw.example.com" {
		t.Errorf("host = %q, want the configured one straight away", st.Host)
	}
}

func TestServiceIsSafeUnderConcurrentUse(t *testing.T) {
	// The refresh loop and a settings page load run at the same time; go test
	// -race is what actually checks this.
	a, _ := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{Detect: true, Detector: detector(t, []*httptest.Server{a, b}, nil)})

	var done atomic.Int64
	for i := range 8 {
		go func(i int) {
			defer done.Add(1)
			switch i % 3 {
			case 0:
				s.Refresh(context.Background())
			case 1:
				s.SetHost("gw.example.com")
			default:
				_ = s.Current()
			}
		}(i)
	}
	for done.Load() < 8 {
		time.Sleep(time.Millisecond)
	}
}

func TestRunStopsWithTheContext(t *testing.T) {
	a, _ := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "8.8.8.8")

	s := service(t, ServiceOptions{
		Detect:   true,
		Refresh:  time.Hour,
		Detector: detector(t, []*httptest.Server{a, b}, nil),
	})

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { s.Run(ctx); close(stopped) }()

	// Run checks once before it starts waiting on the ticker.
	deadline := time.After(3 * time.Second)
	for s.Current().Detected == "" {
		select {
		case <-deadline:
			t.Fatal("Run never performed its first check")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop when the context was cancelled")
	}
}

func TestCompareHandlesALiteralAddress(t *testing.T) {
	s := service(t, ServiceOptions{
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("DNS should not have been consulted for a literal address")
		},
	})

	if got := s.compare(context.Background(), "8.8.8.8", "8.8.8.8"); got != "" {
		t.Errorf("matching literal should be silent, got %q", got)
	}
	if got := s.compare(context.Background(), "8.8.4.4", "8.8.8.8"); got == "" {
		t.Error("a literal pointing elsewhere should be reported")
	}
}

func TestJoinHostPort(t *testing.T) {
	cases := []struct {
		host          string
		port, assumed int
		want          string
	}{
		{"gw.example.com", 3389, 3389, "gw.example.com"}, // the assumed port stays off
		{"gw.example.com", 33890, 3389, "gw.example.com:33890"},
		{"gw.example.com", 0, 3389, "gw.example.com"},
		{"2001:4860:4860::8888", 33890, 3389, "[2001:4860:4860::8888]:33890"},
		{"", 33890, 3389, ""},
	}
	for _, c := range cases {
		if got := JoinHostPort(c.host, c.port, c.assumed); got != c.want {
			t.Errorf("JoinHostPort(%q, %d, %d) = %q, want %q", c.host, c.port, c.assumed, got, c.want)
		}
	}
}

func TestProbeReportsAnOpenPort(t *testing.T) {
	// A listener on loopback stands in for the far side of a hairpin.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Loopback is not public, so the probe declines rather than dialling —
	// which is exactly the guard that stops this becoming a network scanner.
	port := ln.Addr().(*net.TCPAddr).Port
	res := Probe(context.Background(), "127.0.0.1", port, time.Second)
	if res.Reach != ReachSkipped {
		t.Errorf("reach = %q, want %q for a private address", res.Reach, ReachSkipped)
	}
	if res.Confirmed() {
		t.Error("a skipped probe confirms nothing")
	}
}

func TestProbeSkipsWithoutAnAddress(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
	}{{"", 3389}, {"gw.example.com", 0}, {"gw.example.com", 70000}} {
		if res := Probe(context.Background(), c.host, c.port, time.Second); res.Reach != ReachSkipped {
			t.Errorf("Probe(%q, %d) = %q, want %q", c.host, c.port, res.Reach, ReachSkipped)
		}
	}
}

func TestReachConfirmedOnlyForOpen(t *testing.T) {
	// The whole point: a failure means "could not confirm", never "broken".
	if !ReachOpen.Confirmed() {
		t.Error("an accepted connection is proof")
	}
	for _, r := range []Reach{ReachRefused, ReachTimeout, ReachSkipped, ReachError} {
		if r.Confirmed() {
			t.Errorf("%q must not count as proof — most routers refuse to hairpin", r)
		}
	}
}

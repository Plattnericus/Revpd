package netcheck

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	The public address, kept current while the gateway runs.

	Home connections change address, so this is not something to look up once
	at startup and believe forever. It refreshes on a timer, and an operator
	can force a check from the settings page when they have just changed
	something on the router and want to know whether it took.

	A configured domain always wins over a detected address. Detection still
	runs alongside it when it is switched on, purely so a domain that has
	stopped pointing here can be reported — a dynamic-DNS record that quietly
	went stale is the difference between "I can get in from anywhere" and
	finding out otherwise while away from the machine.
*/

// State is everything known about how the gateway is reached, as one
// consistent snapshot.
type State struct {
	// Host is the effective address: the configured domain if there is one,
	// otherwise whatever was detected. Empty when neither is available.
	Host string `json:"host"`

	Source Source `json:"source,omitempty"`

	// Configured is the domain an operator set, kept separate from Host so the
	// interface can show that it is overriding detection.
	Configured string `json:"configured,omitempty"`

	// Detected is the address the outside world reported seeing, even when a
	// configured domain is in force.
	Detected string `json:"detected,omitempty"`

	// DetectedSource is how Detected was arrived at, which is not the same
	// question as where Host came from. Kept apart so clearing a configured
	// host hands the answer straight back to detection without a fresh check.
	DetectedSource Source `json:"detected_source,omitempty"`

	Agreed  int      `json:"agreed,omitempty"`
	Answers []Answer `json:"answers,omitempty"`

	CheckedAt time.Time `json:"checked_at,omitempty"`

	// Error explains why there is no detected address. It is advisory: a
	// failed detection is not an outage, it just means nothing can be
	// suggested.
	Error string `json:"error,omitempty"`

	// Mismatch is set when the configured domain resolves somewhere other than
	// the detected address. Almost always a dynamic-DNS record that has not
	// caught up, and worth saying out loud.
	Mismatch string `json:"mismatch,omitempty"`
}

// Configured reports whether a host was set rather than detected.
func (s State) IsConfigured() bool { return s.Configured != "" }

type ServiceOptions struct {
	// Host is the configured domain or address. Empty falls back to detection.
	Host string

	// Detect turns the outside lookup on. Off means the gateway never talks to
	// a third party about its own address, and only a configured host is used.
	Detect bool

	// Refresh is how often to look again. Zero picks a sane hour.
	Refresh time.Duration

	// MinInterval is the floor between forced checks, so the button on the
	// settings page cannot be leaned on.
	MinInterval time.Duration

	Detector *Detector

	// Lookup resolves the configured domain for the staleness check. Nil uses
	// DNS; tests supply their own.
	Lookup func(ctx context.Context, host string) ([]net.IP, error)

	Now func() time.Time
}

type Service struct {
	detect      bool
	refresh     time.Duration
	minInterval time.Duration
	det         *Detector
	lookup      func(ctx context.Context, host string) ([]net.IP, error)
	now         func() time.Time

	// one serialises checks: two of them at once would ask every resolver
	// twice to arrive at the same answer.
	one sync.Mutex

	mu    sync.RWMutex
	host  string
	state State
}

const (
	defaultRefresh     = time.Hour
	defaultMinInterval = 10 * time.Second
)

func NewService(o ServiceOptions) *Service {
	s := &Service{
		detect:      o.Detect,
		refresh:     o.Refresh,
		minInterval: o.MinInterval,
		det:         o.Detector,
		lookup:      o.Lookup,
		now:         o.Now,
		host:        strings.TrimSpace(o.Host),
	}

	if s.refresh <= 0 {
		s.refresh = defaultRefresh
	}
	if s.minInterval <= 0 {
		s.minInterval = defaultMinInterval
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.det == nil {
		s.det = New(Options{})
	}
	if s.lookup == nil {
		s.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}

	// So the settings page has something to show before the first check
	// finishes, rather than a blank where the address goes.
	s.state = State{Host: s.host, Configured: s.host}
	if s.host != "" {
		s.state.Source = SourceConfigured
	}
	return s
}

// Current returns the last known state without asking anyone.
func (s *Service) Current() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// SetHost applies a configured host that has just been changed.
//
// This takes effect immediately rather than at the next restart, which it can
// afford to: the value is only ever displayed or written into a .rdp file, and
// no listener or certificate depends on it.
func (s *Service) SetHost(host string) {
	host = strings.TrimSpace(host)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.host == host {
		return
	}
	s.host = host
	s.state.Configured = host
	s.state.Mismatch = ""
	s.state = withEffectiveHost(s.state, host)
}

// Refresh looks again, unless the last look was very recent.
//
// The floor is what makes this safe to expose as a button: a held-down key
// costs one round of questions, not hundreds.
func (s *Service) Refresh(ctx context.Context) State {
	s.one.Lock()
	defer s.one.Unlock()

	current := s.Current()
	if !current.CheckedAt.IsZero() && s.now().Sub(current.CheckedAt) < s.minInterval {
		return current
	}
	return s.check(ctx)
}

// Run refreshes on a timer until the context is cancelled.
func (s *Service) Run(ctx context.Context) {
	s.one.Lock()
	s.check(ctx)
	s.one.Unlock()

	ticker := time.NewTicker(s.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.one.Lock()
			s.check(ctx)
			s.one.Unlock()
		}
	}
}

// check does the work. Callers hold s.one.
func (s *Service) check(ctx context.Context) State {
	s.mu.RLock()
	host := s.host
	s.mu.RUnlock()

	next := State{Configured: host, CheckedAt: s.now()}

	if s.detect {
		res, err := s.det.Detect(ctx)
		next.Answers = res.Answers
		if err != nil {
			next.Error = err.Error()
		} else {
			next.Detected = res.IP.String()
			next.DetectedSource = res.Source
			next.Agreed = res.Agreed
		}
	}

	next = withEffectiveHost(next, host)

	// Only worth comparing when there are two things to compare.
	if host != "" && next.Detected != "" {
		next.Mismatch = s.compare(ctx, host, next.Detected)
	}

	s.mu.Lock()
	s.state = next
	s.mu.Unlock()

	if next.Error != "" {
		slog.Debug("could not detect the public address", "err", next.Error)
	}
	if next.Mismatch != "" {
		slog.Warn("the configured public host does not point here", "detail", next.Mismatch)
	}
	return next
}

// compare checks that the configured domain still resolves to where we are.
// It returns the complaint, or empty when everything lines up.
func (s *Service) compare(ctx context.Context, host, detected string) string {
	// An address typed instead of a domain needs no lookup, only a comparison.
	if ip := net.ParseIP(host); ip != nil {
		if ip.String() == detected {
			return ""
		}
		return "web is told to use " + host + ", but this gateway appears on the internet as " + detected
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := s.lookup(ctx, host)
	if err != nil {
		return host + " could not be looked up: " + err.Error()
	}
	for _, ip := range ips {
		if ip.String() == detected {
			return ""
		}
	}

	got := make([]string, 0, len(ips))
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	if len(got) == 0 {
		return host + " does not resolve to any address"
	}
	return host + " points at " + strings.Join(got, ", ") + ", but this gateway appears on the internet as " + detected
}

// withEffectiveHost fills in Host and Source from what is available. A
// configured host wins; a detected address is the fallback.
func withEffectiveHost(st State, configured string) State {
	switch {
	case configured != "":
		st.Host = configured
		st.Source = SourceConfigured
	case st.Detected != "":
		st.Host = st.Detected
		st.Source = st.DetectedSource
	default:
		st.Host = ""
		st.Source = ""
	}
	return st
}

/* ------------------------------------------------------------ endpoint --- */

// JoinHostPort is net.JoinHostPort with the port dropped when it is the one
// the client would have assumed anyway, so the common case reads as a plain
// address rather than one with a number stuck on the end.
func JoinHostPort(host string, port, assumed int) string {
	if host == "" {
		return ""
	}
	if port <= 0 || port == assumed {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

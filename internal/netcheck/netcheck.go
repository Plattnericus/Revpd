// Package netcheck works out how the gateway is reached from the internet.
//
// Telling somebody where to point their RDP client takes two things a
// listening socket cannot supply: the address the outside world sees, and the
// port the router forwards to us. Behind NAT the socket only ever sees the
// LAN, so both have to come from somewhere else — an interface that happens to
// carry a public address, an operator who typed a domain, or a question asked
// of a machine on the other side of the NAT.
//
// Nothing here decides anything. The address is for display, for the .rdp file
// and for the port-forward hint, and no authorization ever reads it. That
// separation is the point: part of this comes from a third party, and a third
// party can lie.
package netcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source says where an address came from. Worth reporting, because the three
// differ in how much they can be trusted and how much they cost to obtain.
type Source string

const (
	// SourceConfigured is a domain or address an operator typed. It wins over
	// everything else — somebody who names their own address means it.
	SourceConfigured Source = "configured"

	// SourceInterface is a public address bound to this machine, which is what
	// a VPS looks like. Free and unimpeachable: nobody was asked.
	SourceInterface Source = "interface"

	// SourceResolver is what machines on the far side of the NAT reported
	// seeing. The normal case at home, and the only one involving a stranger.
	SourceResolver Source = "resolver"
)

// ErrNoResolvers means detection was asked for with nowhere to ask.
var ErrNoResolvers = errors.New("no resolvers configured to ask")

// Answer is one resolver's reply, kept whether or not it was any good so a
// disagreement can be shown rather than quietly resolved.
type Answer struct {
	Resolver string `json:"resolver"`
	IP       string `json:"ip,omitempty"`
	Err      string `json:"error,omitempty"`
}

// Result is one answer to "what does the internet see".
type Result struct {
	IP     net.IP `json:"-"`
	Source Source `json:"source"`

	// Agreed is how many resolvers returned this same address. Zero for the
	// other sources, where there is nobody to agree with.
	Agreed int `json:"agreed,omitempty"`

	Answers   []Answer  `json:"answers,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Options configures a Detector. The zero value is not useful; Defaults in
// package config supplies the real ones.
type Options struct {
	// Resolvers are HTTPS URLs that answer with the caller's address and
	// nothing else. Asked in parallel, and at least two have to agree.
	Resolvers []string

	// Timeout bounds one round of questions, not one question.
	Timeout time.Duration

	// Client asks them. Nil builds a deliberately boring one.
	Client *http.Client

	// LocalIPs reads this machine's own addresses. Nil uses the real
	// interfaces; tests supply their own.
	LocalIPs func() ([]net.IP, error)

	// Now is the clock. Nil is time.Now.
	Now func() time.Time
}

type Detector struct {
	resolvers []string
	timeout   time.Duration
	client    *http.Client
	localIPs  func() ([]net.IP, error)
	now       func() time.Time
}

// defaultTimeout keeps a stalled resolver from holding up a settings page.
const defaultTimeout = 8 * time.Second

// maxAnswer caps what a resolver may send. An address is under 40 bytes; the
// slack is for a trailing newline and nothing more. A resolver that decides to
// stream a gigabyte at us gets cut off instead of being believed.
const maxAnswer = 128

func New(o Options) *Detector {
	d := &Detector{
		timeout:  o.Timeout,
		client:   o.Client,
		localIPs: o.LocalIPs,
		now:      o.Now,
	}

	// Copied rather than aliased: the caller's slice may be a config field
	// that gets rewritten under us when settings change.
	d.resolvers = append([]string(nil), o.Resolvers...)

	if d.timeout <= 0 {
		d.timeout = defaultTimeout
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.localIPs == nil {
		d.localIPs = localIPs
	}
	if d.client == nil {
		d.client = safeClient(d.timeout)
	}
	return d
}

// safeClient is the HTTP client used to ask a stranger a question.
//
// Redirects are refused rather than followed: a resolver that wants to send us
// somewhere else is either broken or hostile, and following it would turn a
// fixed list of endpoints into an open one. Everything else here is about not
// keeping state with a party we have no relationship with.
func safeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("resolver tried to redirect")
		},
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DisableKeepAlives:   true,
			MaxIdleConns:        1,
			TLSHandshakeTimeout: timeout,
		},
	}
}

// Detect works out the public address, cheapest and most trustworthy first.
func (d *Detector) Detect(ctx context.Context) (Result, error) {
	// A machine with a public address on an interface — every VPS — already
	// knows the answer. Asking anyone would leak the question for nothing.
	if ips, err := d.localIPs(); err == nil {
		for _, ip := range ips {
			if IsPublic(ip) {
				return Result{IP: ip, Source: SourceInterface, CheckedAt: d.now()}, nil
			}
		}
	}

	if len(d.resolvers) == 0 {
		return Result{CheckedAt: d.now()}, ErrNoResolvers
	}

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	answers := d.ask(ctx)
	res := Result{Source: SourceResolver, Answers: answers, CheckedAt: d.now()}

	winner, votes := tally(answers)
	if winner == nil {
		return res, fmt.Errorf("no resolver could be reached: %s", summarise(answers))
	}

	// One resolver saying something is a claim; two saying the same thing is
	// evidence. With only one configured there is nothing to cross-check
	// against, and refusing to work would be worse than saying where it came
	// from — which Result.Agreed does.
	if quorum := d.quorum(); votes < quorum {
		return res, fmt.Errorf("resolvers disagree, need %d to match: %s", quorum, summarise(answers))
	}

	res.IP = winner
	res.Agreed = votes
	return res, nil
}

// quorum is how many resolvers have to agree. Two whenever two are available,
// so one compromised endpoint cannot move the answer on its own.
func (d *Detector) quorum() int {
	if len(d.resolvers) < 2 {
		return 1
	}
	return 2
}

// ask puts the question to every resolver at once. One slow endpoint should
// cost the round its own latency, not the sum of all of them.
func (d *Detector) ask(ctx context.Context) []Answer {
	out := make([]Answer, len(d.resolvers))

	var wg sync.WaitGroup
	for i, url := range d.resolvers {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()

			a := Answer{Resolver: hostOf(url)}
			ip, err := d.askOne(ctx, url)
			if err != nil {
				a.Err = err.Error()
			} else {
				a.IP = ip.String()
			}
			out[i] = a
		}(i, url)
	}
	wg.Wait()

	return out
}

func (d *Detector) askOne(ctx context.Context, url string) (net.IP, error) {
	if err := CheckResolver(url); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Some of these serve a whole HTML page to a browser and a bare address to
	// anything else. Asking for text is what gets the short answer.
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "revpd")

	resp, err := d.client.Do(req)
	if err != nil {
		// The full URL is already in there and would repeat it.
		return nil, errors.New(trimURL(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return nil, fmt.Errorf("could not be read: %w", err)
	}

	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return nil, errors.New("did not answer with an address")
	}
	if !IsPublic(ip) {
		// A resolver reporting a private address means the request never left
		// the building — a captive portal or a proxy answered instead.
		return nil, fmt.Errorf("answered with %s, which is not a public address", ip)
	}
	return ip, nil
}

// tally picks the address the most resolvers agreed on. Ties break on the
// text of the address so the same disagreement reads the same way twice.
func tally(answers []Answer) (net.IP, int) {
	votes := map[string]int{}
	for _, a := range answers {
		if a.IP != "" {
			votes[a.IP]++
		}
	}
	if len(votes) == 0 {
		return nil, 0
	}

	keys := make([]string, 0, len(votes))
	for k := range votes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if votes[keys[i]] != votes[keys[j]] {
			return votes[keys[i]] > votes[keys[j]]
		}
		return keys[i] < keys[j]
	})

	return net.ParseIP(keys[0]), votes[keys[0]]
}

func summarise(answers []Answer) string {
	parts := make([]string, 0, len(answers))
	for _, a := range answers {
		if a.IP != "" {
			parts = append(parts, a.Resolver+" said "+a.IP)
		} else {
			parts = append(parts, a.Resolver+" "+a.Err)
		}
	}
	return strings.Join(parts, "; ")
}

/* ---------------------------------------------------------- validation --- */

// CheckResolver rejects a resolver URL that should never be asked.
//
// Plain HTTP is refused outright. The answer decides what address the portal
// tells everybody to connect to, and over HTTP anyone on the path can choose
// it — which turns a display value into a way to point users somewhere else.
func CheckResolver(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("resolver URL is empty")
	}
	if !strings.HasPrefix(raw, "https://") {
		return fmt.Errorf("%q must start with https:// — over plain HTTP the answer can be changed in transit", raw)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("%q contains whitespace", raw)
	}
	return nil
}

// IsPublic reports whether the internet could route back to this address.
//
// Everything a NAT or a lab hands out has to be excluded, or a "detected
// public address" would be a LAN address with extra steps — and the portal
// would confidently tell people to connect somewhere that cannot be reached.
func IsPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}

	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64/10, carrier-grade NAT
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0/24, IETF protocol assignments
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // 192.0.2/24, TEST-NET-1
			return false
		case v4[0] == 198 && v4[1]&0xfe == 18: // 198.18/15, benchmarking
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // 198.51.100/24, TEST-NET-2
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // 203.0.113/24, TEST-NET-3
			return false
		case v4[0] >= 240: // 240/4 reserved, and the broadcast address with it
			return false
		}
		return true
	}

	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	// 2001:db8::/32 is the documentation range, and 100::/64 is the discard
	// prefix — both look global and neither goes anywhere.
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 {
		return false
	}
	if v6[0] == 0x01 && v6[1] == 0x00 && v6[2] == 0 && v6[3] == 0 &&
		v6[4] == 0 && v6[5] == 0 && v6[6] == 0 && v6[7] == 0 {
		return false
	}
	return true
}

/* --------------------------------------------------------------- local --- */

// localIPs lists the addresses bound to this machine's interfaces, skipping
// any that are down.
func localIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				out = append(out, ipnet.IP)
			}
		}
	}
	return out, nil
}

/* --------------------------------------------------------------- utils --- */

// hostOf names a resolver by its host, which is what an error should say. The
// full URL adds a scheme and a path nobody needs to read twice.
func hostOf(raw string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return raw
	}
	return s
}

// trimURL drops the URL that net/http prefixes onto its errors, since the
// resolver is already named beside the message.
func trimURL(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "Get ") {
		return msg[i+2:]
	}
	return msg
}

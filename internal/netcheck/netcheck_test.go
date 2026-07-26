package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946",
	}
	for _, s := range public {
		if !IsPublic(net.ParseIP(s)) {
			t.Errorf("%s should be public", s)
		}
	}

	// Every one of these would send somebody to an address that cannot be
	// reached from outside, so each has to be rejected by name.
	private := []string{
		"0.0.0.0",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.1",
		"169.254.1.1", // link-local
		"100.64.0.1",  // carrier-grade NAT
		"100.127.255.255",
		"192.0.0.1",    // IETF assignments
		"192.0.2.1",    // TEST-NET-1
		"198.18.0.1",   // benchmarking
		"198.19.255.1", // benchmarking
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
		"240.0.0.1",    // reserved
		"255.255.255.255",
		"224.0.0.1", // multicast
		"::1",
		"fe80::1",      // link-local
		"fc00::1",      // unique local
		"fd12:3456::1", // unique local
		"2001:db8::1",  // documentation
		"100::1",       // discard
	}
	for _, s := range private {
		if IsPublic(net.ParseIP(s)) {
			t.Errorf("%s should not count as public", s)
		}
	}

	if IsPublic(nil) {
		t.Error("nil should not be public")
	}
}

func TestCheckResolverRejectsPlainHTTP(t *testing.T) {
	// The answer decides what address the portal tells everyone to use. Over
	// HTTP anyone on the path picks it, so this must never be allowed.
	for _, bad := range []string{"", "http://example.com", "ftp://x", "example.com", "https://a b"} {
		if err := CheckResolver(bad); err == nil {
			t.Errorf("CheckResolver(%q) should have failed", bad)
		}
	}
	if err := CheckResolver("https://api.example.com/ip"); err != nil {
		t.Errorf("a plain https URL should be accepted: %v", err)
	}
}

// tlsServer stands in for a real resolver. TLS rather than plain HTTP because
// the detector refuses anything else, and that rule is worth exercising rather
// than working around.
func tlsServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// resolver serves a fixed body and counts how often it was asked.
func resolver(t *testing.T, body string) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	return tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body))
	}), &hits
}

// trust builds a pool holding exactly the test servers' own certificates, so
// the client verifies for real instead of being told to skip it.
func trust(servers []*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range servers {
		if c := s.Certificate(); c != nil {
			pool.AddCert(c)
		}
	}
	return pool
}

// detector wires a Detector to test servers.
func detector(t *testing.T, servers []*httptest.Server, local []net.IP) *Detector {
	t.Helper()

	urls := make([]string, 0, len(servers))
	for _, s := range servers {
		urls = append(urls, s.URL)
	}

	d := New(Options{
		Resolvers: urls,
		Timeout:   2 * time.Second,
		LocalIPs:  func() ([]net.IP, error) { return local, nil },
		Now:       func() time.Time { return time.Unix(1700000000, 0) },
	})

	// The real client, with the test certificates added to what it trusts.
	// Everything else about it — the redirect rule, the timeouts — stays as
	// it ships.
	d.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trust(servers)}
	return d
}

func TestDetectPrefersALocalPublicAddress(t *testing.T) {
	srv, hits := resolver(t, "9.9.9.9")

	// A machine with a public address on an interface knows the answer
	// already. Asking anyone would leak the question for nothing.
	d := detector(t, []*httptest.Server{srv}, []net.IP{
		net.ParseIP("192.168.1.10"),
		net.ParseIP("203.0.113.9"), // TEST-NET, must not be taken as public
		net.ParseIP("8.8.4.4"),
	})

	res, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if res.Source != SourceInterface || res.IP.String() != "8.8.4.4" {
		t.Fatalf("got %s from %s, want 8.8.4.4 from the interface", res.IP, res.Source)
	}
	if hits.Load() != 0 {
		t.Errorf("no resolver should have been asked, got %d calls", hits.Load())
	}
}

func TestDetectNeedsTwoResolversToAgree(t *testing.T) {
	a, _ := resolver(t, "203.0.113.0\n") // rejected: not a public address
	b, _ := resolver(t, "8.8.8.8\n")
	c, _ := resolver(t, "8.8.8.8")

	d := detector(t, []*httptest.Server{a, b, c}, nil)

	res, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if res.IP.String() != "8.8.8.8" {
		t.Fatalf("got %s, want 8.8.8.8", res.IP)
	}
	if res.Agreed != 2 {
		t.Errorf("agreed = %d, want 2", res.Agreed)
	}
	if res.Source != SourceResolver {
		t.Errorf("source = %s, want %s", res.Source, SourceResolver)
	}
	if len(res.Answers) != 3 {
		t.Fatalf("every resolver should be reported, got %d", len(res.Answers))
	}
}

func TestDetectRefusesASingleDissentingResolver(t *testing.T) {
	// One endpoint saying something is a claim, not evidence: a compromised
	// resolver must not be able to move the answer by itself.
	a, _ := resolver(t, "8.8.8.8")
	b, _ := resolver(t, "1.1.1.1")

	d := detector(t, []*httptest.Server{a, b}, nil)

	if _, err := d.Detect(context.Background()); err == nil {
		t.Fatal("two resolvers disagreeing should not produce an address")
	} else if !strings.Contains(err.Error(), "disagree") {
		t.Errorf("the error should say they disagree: %v", err)
	}
}

func TestDetectWithOneResolverAcceptsIt(t *testing.T) {
	// Nothing to cross-check against, so the answer is taken and Agreed says
	// how thin the evidence is.
	a, _ := resolver(t, "8.8.8.8")

	res, err := detector(t, []*httptest.Server{a}, nil).Detect(context.Background())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if res.Agreed != 1 {
		t.Errorf("agreed = %d, want 1", res.Agreed)
	}
}

func TestDetectRejectsPrivateAndJunkAnswers(t *testing.T) {
	// A private address means the request never left the building; a page of
	// HTML means something answered that was not a resolver.
	private, _ := resolver(t, "192.168.1.1")
	junk, _ := resolver(t, "<html>not an address</html>")

	res, err := detector(t, []*httptest.Server{private, junk}, nil).Detect(context.Background())
	if err == nil {
		t.Fatal("neither answer should have been believed")
	}
	for _, a := range res.Answers {
		if a.IP != "" {
			t.Errorf("%s answered %s and should have been rejected", a.Resolver, a.IP)
		}
	}
}

func TestDetectCapsTheResponseBody(t *testing.T) {
	// A resolver that streams at us gets cut off rather than believed.
	flood := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("8.8.8.8" + strings.Repeat("0", 10<<20)))
	})

	res, err := detector(t, []*httptest.Server{flood}, nil).Detect(context.Background())
	if err == nil {
		t.Fatalf("a truncated flood should not parse as an address, got %s", res.IP)
	}
}

func TestDetectRefusesRedirects(t *testing.T) {
	// Following a redirect would turn a fixed list of endpoints into an open
	// one, and let a resolver choose who answers for it.
	elsewhere, _ := resolver(t, "8.8.8.8")
	redirector := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	})

	d := detector(t, []*httptest.Server{redirector, elsewhere}, nil)
	d.resolvers = []string{redirector.URL}

	if _, err := d.Detect(context.Background()); err == nil {
		t.Fatal("a redirecting resolver should not be followed")
	}
}

func TestDetectWithNoResolvers(t *testing.T) {
	if _, err := detector(t, nil, nil).Detect(context.Background()); err != ErrNoResolvers {
		t.Fatalf("err = %v, want %v", err, ErrNoResolvers)
	}
}

func TestDetectReportsUnreachableResolvers(t *testing.T) {
	dead, _ := resolver(t, "8.8.8.8")
	d := detector(t, []*httptest.Server{dead}, nil)
	dead.Close() // nothing is listening any more

	res, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("an unreachable resolver should not produce an address")
	}
	if len(res.Answers) != 1 || res.Answers[0].Err == "" {
		t.Fatalf("the failure should be reported per resolver: %+v", res.Answers)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://api.ipify.org?format=text": "api.ipify.org",
		"https://ifconfig.co/ip":            "ifconfig.co",
		"https://icanhazip.com":             "icanhazip.com",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

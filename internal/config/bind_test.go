package config

import (
	"net"
	"strings"
	"testing"
)

/*
	Binding with fallbacks. The point of these is the awkward case: the port
	somebody expects is taken, and the gateway has to come up anyway and be
	honest about where it ended up.
*/

// takePort occupies a port and returns its address, so the next bind has to
// deal with a real conflict rather than a simulated one.
func takePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestListenTakesThePrimaryWhenItIsFree(t *testing.T) {
	b, err := Listen("tcp", "127.0.0.1:0", []string{"127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Listener.Close()

	if b.FellBack {
		t.Error("reported a fallback although the first address was free")
	}
	if len(b.Tried) != 0 {
		t.Errorf("nothing should have been refused, got %v", b.Tried)
	}
}

func TestListenMovesToTheFallback(t *testing.T) {
	taken := takePort(t)

	b, err := Listen("tcp", taken, []string{"127.0.0.1:0"})
	if err != nil {
		t.Fatalf("did not fall back: %v", err)
	}
	defer b.Listener.Close()

	if !b.FellBack {
		t.Error("fell back but did not say so")
	}
	if b.Addr == taken {
		t.Error("claims to have bound the port that was already taken")
	}

	// The reason has to be in there, or the log says nothing useful.
	if len(b.Tried) != 1 || !strings.Contains(b.Tried[0], "already in use") {
		t.Errorf("the refusal was not explained: %v", b.Tried)
	}
}

func TestListenWalksTheWholeList(t *testing.T) {
	first, second := takePort(t), takePort(t)

	b, err := Listen("tcp", first, []string{second, "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Listener.Close()

	if !b.FellBack || len(b.Tried) != 2 {
		t.Errorf("expected two refusals before binding, got %v", b.Tried)
	}
}

// When nothing works the error has to name every address and why each failed —
// that is the whole diagnosis, and there is no second chance to collect it.
func TestListenReportsEveryAddressItTried(t *testing.T) {
	a, b2 := takePort(t), takePort(t)

	_, err := Listen("tcp", a, []string{b2})
	if err == nil {
		t.Fatal("bound something although every address was taken")
	}
	for _, want := range []string{a, b2, "already in use"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestListenNeedsAnAddress(t *testing.T) {
	if _, err := Listen("tcp", "", nil); err == nil {
		t.Fatal("accepted an empty address")
	}
}

func TestListenSkipsEmptyFallbacks(t *testing.T) {
	taken := takePort(t)

	b, err := Listen("tcp", taken, []string{"", "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("an empty entry in the list broke the fallback: %v", err)
	}
	b.Listener.Close()
}

/* ------------------------------------------------------------ addresses --- */

func TestPortalURLHidesTheDefaultPort(t *testing.T) {
	cases := []struct {
		hostname, listen, want string
	}{
		// 443 is what a browser assumes, so showing it is noise.
		{"gw.example.com", ":443", "https://gw.example.com"},
		{"gw.example.com", "0.0.0.0:443", "https://gw.example.com"},

		// Anything else has to be typed, so it has to be shown.
		{"gw.example.com", ":8443", "https://gw.example.com:8443"},
		{"gw.example.com", "127.0.0.1:9443", "https://gw.example.com:9443"},

		// IPv6 hostnames still have to come out as a usable URL.
		{"::1", ":8443", "https://[::1]:8443"},
	}

	for _, c := range cases {
		if got := PortalURL(c.hostname, c.listen); got != c.want {
			t.Errorf("PortalURL(%q, %q) = %q, want %q", c.hostname, c.listen, got, c.want)
		}
	}
}

func TestPortExtractsThePort(t *testing.T) {
	if got := Port(":8443"); got != "8443" {
		t.Errorf("Port(:8443) = %q", got)
	}
	if got := Port("nonsense"); got != "" {
		t.Errorf("Port(nonsense) = %q, want empty", got)
	}
}

/* -------------------------------------------------------------- defaults -- */

// The ports a browser assumes, with two alternatives each. Getting these wrong
// means a fresh install lands somewhere nobody thinks to look.
func TestDefaultPorts(t *testing.T) {
	w := Defaults().Web

	if Port(w.Listen) != "443" {
		t.Errorf("the portal defaults to %q, want :443", w.Listen)
	}
	if Port(w.HTTPListen) != "80" {
		t.Errorf("the redirect defaults to %q, want :80", w.HTTPListen)
	}
	if len(w.ListenFallbacks) != 2 {
		t.Errorf("want two fallbacks for the portal, got %v", w.ListenFallbacks)
	}
	if len(w.HTTPListenFallbacks) != 2 {
		t.Errorf("want two fallbacks for the redirect, got %v", w.HTTPListenFallbacks)
	}

	// A fallback that collides with the primary would be pointless.
	for _, f := range w.ListenFallbacks {
		if f == w.Listen {
			t.Errorf("fallback %q is the primary address", f)
		}
	}
	for _, f := range w.HTTPListenFallbacks {
		if f == w.HTTPListen {
			t.Errorf("fallback %q is the primary address", f)
		}
	}

	// The two lists must not overlap, or one service would take the other's
	// fallback and the second would have nowhere left to go.
	for _, a := range w.ListenFallbacks {
		for _, b := range w.HTTPListenFallbacks {
			if a == b {
				t.Errorf("%q is a fallback for both the portal and the redirect", a)
			}
		}
	}
}

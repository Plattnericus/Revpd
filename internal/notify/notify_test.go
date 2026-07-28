package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
)

// received is one delivered notification, as the far end saw it.
type received struct {
	body    string
	title   string
	prio    string
	ctype   string
	decoded map[string]any
}

// sink stands in for ntfy, Discord or whatever else is at the other end.
func sink(t *testing.T) (*httptest.Server, func() []received) {
	t.Helper()

	var (
		mu   sync.Mutex
		got  []received
		fail int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		mu.Lock()
		defer mu.Unlock()
		if fail > 0 {
			fail--
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		rec := received{
			body:  string(body),
			title: r.Header.Get("X-Title"),
			prio:  r.Header.Get("X-Priority"),
			ctype: r.Header.Get("Content-Type"),
		}
		json.Unmarshal(body, &rec.decoded)
		got = append(got, rec)
	}))
	t.Cleanup(srv.Close)

	return srv, func() []received {
		mu.Lock()
		defer mu.Unlock()
		return append([]received(nil), got...)
	}
}

// waitFor polls until cond holds, so the tests do not race the sender
// goroutine or pay for a fixed sleep.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func run(t *testing.T, cfg Config) *Notifier {
	t.Helper()
	n := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		n.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return n
}

func TestOnlyTheChosenEventsAreSent(t *testing.T) {
	srv, got := sink(t)

	n := run(t, Config{
		Enabled: true,
		URL:     srv.URL,
		Format:  FormatNtfy,
		Events:  []string{audit.ActionRelayOpen},
	})

	n.Handle(audit.Entry{Action: audit.ActionLoginOK, Actor: "felix"})
	n.Handle(audit.Entry{Action: audit.ActionRelayOpen, Actor: "felix", Object: "Büro-PC", SrcIP: "203.0.113.9"})
	n.Handle(audit.Entry{Action: audit.ActionRelayClose, Actor: "felix"})

	waitFor(t, "the one wanted event", func() bool { return len(got()) == 1 })

	// Give the other two a chance to arrive wrongly before believing they did not.
	time.Sleep(100 * time.Millisecond)

	all := got()
	if len(all) != 1 {
		t.Fatalf("delivered %d messages, want 1: %+v", len(all), all)
	}
	if all[0].title != "Remote desktop connected" {
		t.Errorf("title = %q", all[0].title)
	}
	for _, want := range []string{"felix", "Büro-PC", "203.0.113.9"} {
		if !strings.Contains(all[0].body, want) {
			t.Errorf("body %q does not mention %q", all[0].body, want)
		}
	}
}

func TestNothingIsSentWhileSwitchedOff(t *testing.T) {
	srv, got := sink(t)

	n := run(t, Config{Enabled: false, URL: srv.URL, Events: []string{audit.ActionLockout}})
	n.Handle(audit.Entry{Action: audit.ActionLockout, Actor: "felix"})

	time.Sleep(100 * time.Millisecond)
	if len(got()) != 0 {
		t.Fatalf("something was sent with notifications off: %+v", got())
	}
}

// A rate limit that silently swallowed events would hide the shape of an
// attack, which is the one time somebody actually reads these.
func TestSuppressedEventsAreCounted(t *testing.T) {
	srv, got := sink(t)

	n := run(t, Config{
		Enabled: true, URL: srv.URL, Format: FormatNtfy,
		Events: []string{audit.ActionLockout},
	})

	// Well past the burst of five.
	for range 12 {
		n.Handle(audit.Entry{Action: audit.ActionLockout, Actor: "felix"})
	}

	waitFor(t, "the burst", func() bool { return len(got()) >= 5 })
	time.Sleep(150 * time.Millisecond)

	all := got()
	if len(all) != 5 {
		t.Fatalf("delivered %d messages, want the burst of 5", len(all))
	}

	// The seven that were held back are admitted to by the next one through.
	n.Handle(audit.Entry{Action: audit.ActionLockout, Actor: "felix"})
	time.Sleep(100 * time.Millisecond)
	if len(got()) != 5 {
		t.Fatalf("a sixth message got through inside the refill window")
	}
}

// Whoever connects chooses the sign-in hint, and it ends up on a phone.
func TestUntrustedFieldsAreCutDownAndCleaned(t *testing.T) {
	m := render(audit.Entry{
		Action: audit.ActionJITRequested,
		Actor:  "felix",
		Object: "Büro-PC",
		SrcIP:  "203.0.113.9",
		Detail: map[string]any{"hint": "admin\r\nX-Title: spoofed\x00" + strings.Repeat("a", 200)},
	})

	// The guarantee is that nothing typed by a stranger can become a line, or a
	// header, of its own. The words survive; their power to break out does not.
	if strings.ContainsAny(m.Body, "\r\x00") {
		t.Errorf("control characters survived: %q", m.Body)
	}
	for _, line := range strings.Split(m.Body, "\n") {
		if strings.HasPrefix(line, "X-") {
			t.Errorf("something typed by a stranger became a line of its own: %q", line)
		}
	}
	if len([]rune(m.Body)) > 200 {
		t.Errorf("body is %d runes, too long for a notification: %q", len([]rune(m.Body)), m.Body)
	}
	if !m.Urgent {
		t.Error("an approval request should be urgent — nobody is watching the portal")
	}
}

func TestEachServiceGetsTheShapeItExpects(t *testing.T) {
	e := audit.Entry{Action: audit.ActionRelayOpen, Actor: "felix", Object: "Büro-PC"}

	cases := []struct {
		format string
		check  func(t *testing.T, r received)
	}{
		{FormatNtfy, func(t *testing.T, r received) {
			if r.title != "Remote desktop connected" {
				t.Errorf("X-Title = %q", r.title)
			}
			if !strings.HasPrefix(r.ctype, "text/plain") {
				t.Errorf("content type = %q", r.ctype)
			}
		}},
		{FormatDiscord, func(t *testing.T, r received) {
			if _, ok := r.decoded["content"].(string); !ok {
				t.Errorf("discord wants a content field, got %v", r.decoded)
			}
		}},
		{FormatSlack, func(t *testing.T, r received) {
			if _, ok := r.decoded["text"].(string); !ok {
				t.Errorf("slack wants a text field, got %v", r.decoded)
			}
		}},
		{FormatJSON, func(t *testing.T, r received) {
			if r.decoded["event"] != audit.ActionRelayOpen {
				t.Errorf("event = %v, want the action name", r.decoded["event"])
			}
		}},
	}

	for _, c := range cases {
		t.Run(c.format, func(t *testing.T) {
			srv, got := sink(t)
			n := run(t, Config{Enabled: true, URL: srv.URL, Format: c.format, Events: []string{e.Action}})

			n.Handle(e)
			waitFor(t, "delivery", func() bool { return len(got()) == 1 })
			c.check(t, got()[0])
		})
	}
}

// A wrong URL is the mistake people make first, so the reason has to survive
// the trip back to the settings page.
func TestTestSaysWhyItFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such topic", http.StatusNotFound)
	}))
	defer srv.Close()

	n := New(Config{Enabled: true, URL: srv.URL, Format: FormatNtfy})

	err := n.Test(context.Background())
	if err == nil {
		t.Fatal("a 404 was reported as success")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, does not say what the server answered", err)
	}
}

func TestTestNeedsSomewhereToSend(t *testing.T) {
	if err := New(Config{Enabled: true}).Test(context.Background()); err == nil {
		t.Fatal("testing with no URL reported success")
	}
}

// A slow endpoint must never become a slow RDP handshake.
func TestHandleDoesNotBlockOnADeadEndpoint(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	n := run(t, Config{
		Enabled: true, URL: srv.URL, Format: FormatNtfy,
		Events:  []string{audit.ActionRelayOpen},
		Timeout: time.Minute,
	})

	done := make(chan struct{})
	go func() {
		// Comfortably more than the queue holds.
		for range queueDepth * 4 {
			n.Handle(audit.Entry{Action: audit.ActionRelayOpen, Actor: "felix"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle blocked while the endpoint was not answering")
	}
}

func TestURLValidation(t *testing.T) {
	ok := []string{
		"",
		"https://ntfy.sh/revpd-alerts",
		"https://discord.com/api/webhooks/1/abc",
		"http://192.168.1.5:8080/publish", // own network: nothing leaves the house
		"http://localhost:2586/alerts",
	}
	for _, u := range ok {
		if err := CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v, want accepted", u, err)
		}
	}

	bad := []string{
		"http://ntfy.sh/revpd-alerts", // the URL is the credential
		"ftp://example.com/x",
		"not a url at all",
		"https://",
		"file:///etc/shadow",
		"javascript:alert(1)",

		// The cloud metadata service. Nothing legitimate listens there, and a
		// notification URL is something this gateway POSTs to on somebody
		// else's schedule.
		"http://169.254.169.254/latest/meta-data/",
		"http://[fe80::1]/publish",
	}
	for _, u := range bad {
		if err := CheckURL(u); err == nil {
			t.Errorf("CheckURL(%q) was accepted", u)
		}
	}
}

func TestEventValidation(t *testing.T) {
	if err := CheckEvents(DefaultEvents()); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
	if err := CheckEvents([]string{"relay.opened"}); err == nil {
		t.Error("a near-miss action name was accepted")
	}

	// Everything offered has to be renderable, or the settings page would let
	// somebody choose an event that then arrives with the action as its title.
	for _, a := range Notifiable() {
		if _, ok := titles[a]; !ok {
			t.Errorf("%q is offered but has no title", a)
		}
		if !audit.KnownAction(a) {
			t.Errorf("%q is offered but is not an audit action", a)
		}
	}
}

func TestFormatValidation(t *testing.T) {
	for _, f := range []string{FormatNtfy, FormatDiscord, FormatSlack, FormatJSON} {
		if err := CheckFormat(f); err != nil {
			t.Errorf("CheckFormat(%q) = %v", f, err)
		}
	}
	if err := CheckFormat("telegram"); err == nil {
		t.Error("an unknown format was accepted")
	}
}

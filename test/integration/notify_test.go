//go:build integration

// The notification settings as the settings page actually receives them, and
// what the test button does at each end of the range.
package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/notify"
)

// settingsByKey pulls the configuration schema the settings page draws from.
func settingsByKey(t *testing.T, e *apiEnv, cookies []*http.Cookie, csrf string) map[string]map[string]any {
	t.Helper()

	resp := e.call(t, "GET", "/api/admin/config", nil, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config returned %d", resp.StatusCode)
	}

	body := decodeBody(t, resp)
	raw, _ := body["settings"].([]any)

	out := map[string]map[string]any{}
	for _, s := range raw {
		if m, ok := s.(map[string]any); ok {
			out[m["key"].(string)] = m
		}
	}
	return out
}

// A drop-down with no options and a list with no allowed values are both
// fields nobody can fill in without reading the source.
func TestNotifySettingsArriveWithTheirChoices(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	settings := settingsByKey(t, e, cookies, csrf)

	format, ok := settings["notify.format"]
	if !ok {
		t.Fatal("notify.format is not offered by the settings page")
	}
	if format["kind"] != "choice" {
		t.Errorf("notify.format kind = %v, want choice", format["kind"])
	}
	opts, _ := format["options"].([]any)
	if len(opts) != 4 {
		t.Errorf("notify.format offers %d formats, want 4: %v", len(opts), opts)
	}

	events, ok := settings["notify.events"]
	if !ok {
		t.Fatal("notify.events is not offered")
	}
	allowed, _ := events["options"].([]any)
	if len(allowed) != len(notify.Notifiable()) {
		t.Errorf("notify.events lists %d allowed values, want %d", len(allowed), len(notify.Notifiable()))
	}

	// Changing where alerts go must not cost anybody their desktop session.
	for _, key := range []string{"notify.enabled", "notify.url", "notify.format", "notify.events"} {
		if settings[key]["restart"] == true {
			t.Errorf("%s claims to need a restart", key)
		}
	}
}

func TestNotifyRefusesADestinationThatLeaks(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/config", map[string]any{
		"values": map[string]string{"notify.url": "http://ntfy.sh/alerts"},
	}, cookies, csrf)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a plain-HTTP destination was accepted: %d", resp.StatusCode)
	}
	if msg, _ := decodeBody(t, resp)["error"].(string); !strings.Contains(msg, "https") {
		t.Errorf("the refusal does not say what is wrong: %q", msg)
	}
}

func TestNotifyRefusesAnEventThatDoesNotExist(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/config", map[string]any{
		"values": map[string]string{"notify.events": "relay.open, relay.opened"},
	}, cookies, csrf)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a misspelled event name was accepted: %d", resp.StatusCode)
	}
}

// The button has to say why rather than fail quietly, and it must not be the
// thing that discovers notifications are off.
func TestNotifyTestNeedsNotificationsOn(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/notify/test", nil, cookies, csrf)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("testing with notifications off returned %d, want 412", resp.StatusCode)
	}
}

// Only administrators may send from this gateway or read where it sends to.
func TestNotifyTestIsAdminOnly(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/admin/notify/test", nil, nil, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an unauthenticated request could make the gateway send a message")
	}
	resp.Body.Close()
}

/*
Something happening in the portal comes out the other end as a message.

This is the whole path in one test: an administrator does something, the
policy code writes it to the audit log without knowing a notifier exists, the
watcher picks it up, and it arrives at a URL. Every piece of that is covered on
its own; only here does it have to fit together.
*/
func TestSomethingThatHappensArrivesAsAMessage(t *testing.T) {
	got := make(chan string, 4)

	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case got <- r.Header.Get("X-Title") + "\n" + string(body):
		default:
		}
	}))
	defer sink.Close()

	e := newAPIWith(t, func(c *config.Config) {
		c.Notify.Enabled = true
		c.Notify.URL = sink.URL
		c.Notify.Format = notify.FormatNtfy
		c.Notify.Events = []string{audit.ActionUserCreated}
	})
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/users", map[string]any{
		"username": "bea", "display_name": "Bea",
		"password": "AnotherLongEnoughOne", "role": "user",
	}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creating a user returned %d", resp.StatusCode)
	}
	decodeBody(t, resp)

	select {
	case msg := <-got:
		if !strings.Contains(msg, "Account created") {
			t.Errorf("the message does not say what happened: %q", msg)
		}
		if !strings.Contains(msg, "bea") {
			t.Errorf("the message does not say who it was about: %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived at the endpoint")
	}
}

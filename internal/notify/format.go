package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/plattnericus/revpd/internal/audit"
)

/*
Turning an audit entry into something readable on a lock screen.

Two rules run through this file.

The first is that a notification says what happened and nothing else. No
password ever reaches the audit log to begin with, but a message is a copy of
an event leaving the machine over somebody else's network, so what goes in it
is chosen by name rather than inherited.

The second is that parts of an entry come from whoever connected. The sign-in
hint in a JIT request is typed into the Remote Desktop client by a stranger,
and it arrives here on its way to a phone. It is cut short and stripped of
anything that is not printable, because a notification is not a place to find
out what a control character does to somebody's notification shade.
*/

// Message is one notification, before it is shaped for a particular service.
type Message struct {
	Title string
	Body  string

	// Event is the audit action, passed through for anything consuming the
	// JSON form and wanting to route on it.
	Event string

	// Urgent raises the priority where the service has one. Reserved for the
	// things somebody would want to see at night.
	Urgent bool

	// Suppressed is how many events were rate-limited or dropped since the
	// last message that got through.
	Suppressed int
}

// titles are what each action is called in a notification. An action missing
// here is not notifiable — the settings page offers this list and nothing else.
var titles = map[string]struct {
	title  string
	urgent bool
}{
	audit.ActionRelayOpen:      {title: "Remote desktop connected"},
	audit.ActionRelayClose:     {title: "Remote desktop disconnected"},
	audit.ActionRelayRejected:  {title: "Connection refused"},
	audit.ActionGrantIssued:    {title: "Access granted"},
	audit.ActionGrantDenied:    {title: "Access denied", urgent: true},
	audit.ActionLoginOK:        {title: "Signed in"},
	audit.ActionLoginFail:      {title: "Sign-in failed"},
	audit.ActionMFAFail:        {title: "Second factor failed"},
	audit.ActionLockout:        {title: "Account locked", urgent: true},
	audit.ActionJITRequested:   {title: "Approval requested", urgent: true},
	audit.ActionJITApproved:    {title: "Approval given"},
	audit.ActionJITDenied:      {title: "Approval refused", urgent: true},
	audit.ActionJITTimeout:     {title: "Approval timed out"},
	audit.ActionWolSent:        {title: "Waking a machine"},
	audit.ActionTargetOnline:   {title: "Machine is up"},
	audit.ActionTargetTimeout:  {title: "Machine did not come up"},
	audit.ActionUserCreated:    {title: "Account created", urgent: true},
	audit.ActionMFAReset:       {title: "Second factor reset", urgent: true},
	audit.ActionSettingsUpdate: {title: "Settings changed"},
	audit.ActionUpdateApplied:  {title: "Update installed"},
}

// Notifiable lists the actions that can be notified on, in the order above's
// rough sense of importance. The settings page validates against this.
func Notifiable() []string {
	out := make([]string, 0, len(titles))
	for _, a := range audit.Actions() { // audit's order, so the list is stable
		if _, ok := titles[a]; ok {
			out = append(out, a)
		}
	}
	return out
}

// DefaultEvents is what a fresh installation notifies on: somebody connected,
// somebody is locked out, somebody is waiting for an approval.
func DefaultEvents() []string {
	return []string{audit.ActionRelayOpen, audit.ActionLockout, audit.ActionJITRequested}
}

func render(e audit.Entry) Message {
	t, ok := titles[e.Action]
	if !ok {
		t.title = e.Action
	}

	m := Message{Title: t.title, Event: e.Action, Urgent: t.urgent}

	// Who, what and from where — the three things worth reading before deciding
	// whether to get up. Each part is optional; several entries have no target.
	var parts []string
	if a := clean(e.Actor, 48); a != "" {
		parts = append(parts, a)
	}
	if o := clean(e.Object, 48); o != "" {
		parts = append(parts, "→ "+o)
	}
	if ip := clean(e.SrcIP, 45); ip != "" {
		parts = append(parts, "from "+ip)
	}
	m.Body = strings.Join(parts, " ")

	// One detail, chosen by name. "reason" is written by us and says why a
	// connection was refused; "hint" is typed by whoever connected and is the
	// only field here that a stranger controls.
	if r, _ := e.Detail["reason"].(string); r != "" {
		m.Body = appendLine(m.Body, "Reason: "+clean(r, 80))
	}
	if h, _ := e.Detail["hint"].(string); h != "" {
		m.Body = appendLine(m.Body, "Name given: "+clean(h, 40))
	}

	if m.Body == "" {
		m.Body = e.TS.Format(time.RFC1123)
	}
	return m
}

func appendLine(body, line string) string {
	if body == "" {
		return line
	}
	return body + "\n" + line
}

// clean makes a string safe to put in a notification: printable characters
// only, no line of its own, and short enough not to push everything else off
// the screen.
//
// Control characters become a space rather than nothing. Dropping them would
// weld "admin" and the line somebody appended to it into one word, which reads
// like a name that was really there instead of like the two pieces it is.
func clean(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")

	if len([]rune(s)) > limit {
		s = string([]rune(s)[:limit]) + "…"
	}
	return s
}

// text is the message as one block, for the services that take one.
func (m Message) text() string {
	out := m.Body
	if m.Suppressed > 0 {
		out = appendLine(out, fmt.Sprintf("(%d further events were not sent)", m.Suppressed))
	}
	return out
}

/* ------------------------------------------------------------ delivery --- */

func request(ctx context.Context, cfg Config, m Message) (*http.Request, error) {
	switch cfg.Format {
	case FormatDiscord:
		return jsonRequest(ctx, cfg.URL, map[string]any{
			"content": "**" + m.Title + "**\n" + m.text(),
		})

	case FormatSlack:
		return jsonRequest(ctx, cfg.URL, map[string]any{
			"text": "*" + m.Title + "*\n" + m.text(),
		})

	case FormatJSON:
		return jsonRequest(ctx, cfg.URL, map[string]any{
			"event":      m.Event,
			"title":      m.Title,
			"body":       m.text(),
			"urgent":     m.Urgent,
			"suppressed": m.Suppressed,
			"ts":         time.Now().UTC().Format(time.RFC3339),
		})

	case FormatNtfy, "":
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL,
			strings.NewReader(m.text()))
		if err != nil {
			return nil, fmt.Errorf("build notification request: %w", err)
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")

		// Titles are ours and stay ASCII on purpose: this one travels in a
		// header, and a target name with an umlaut in it belongs in the body.
		req.Header.Set("X-Title", m.Title)
		if m.Urgent {
			req.Header.Set("X-Priority", "high")
		}
		return req, nil

	default:
		return nil, fmt.Errorf("%q is not a notification format this knows", cfg.Format)
	}
}

func jsonRequest(ctx context.Context, url string, payload map[string]any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build notification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

/* ---------------------------------------------------------- validation --- */

// CheckFormat rejects anything request() would not know what to do with.
func CheckFormat(v string) error {
	switch v {
	case FormatNtfy, FormatDiscord, FormatSlack, FormatJSON:
		return nil
	}
	return fmt.Errorf("%q is not a format — use ntfy, discord, slack or json", v)
}

// CheckURL insists on HTTPS to anywhere that is not on this network.
//
// These URLs are bearer credentials in their own right: a Discord webhook or an
// ntfy topic is whoever knows it. Over plain HTTP the first machine on the path
// would learn it, and could then send notifications that look like ours.
func CheckURL(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}

	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("%q is not a URL", v)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host — it should look like https://ntfy.sh/your-topic", v)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLocal(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%q must use https — the URL is itself the password to that channel", v)
	default:
		return fmt.Errorf("%q must start with https://", v)
	}
}

// CheckEvents rejects action names that do not exist or cannot be notified on,
// so a typo is caught while somebody is looking at the field rather than by its
// silence a month later.
func CheckEvents(list []string) error {
	for _, e := range list {
		if _, ok := titles[e]; !ok {
			return fmt.Errorf("%q is not an event that can be notified on — see the list under the field", e)
		}
	}
	return nil
}

// isLocal is what plain HTTP is forgiven for: a machine on your own network,
// where the URL never crosses anything you do not run.
//
// Link-local is deliberately not on that list. 169.254.169.254 is the metadata
// service on every cloud host, and a notification destination is a URL this
// gateway will POST to on a schedule somebody else chooses. There is no such
// thing as a self-hosted ntfy at that address, so allowing it buys nothing and
// hands an administrator account a way to reach into the host it runs on.
func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

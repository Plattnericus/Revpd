/*
Package notify tells a person that something happened on the gateway.

It hangs off the audit log rather than off the places where things happen.
Everything worth knowing about is already written there — a desktop session
opening, an account locking itself, an approval waiting for an answer — and the
alternative is a call to a notifier sprinkled through the relay, the policy
engine and the login path, each of them a place to forget one.

Nothing here can hold anything up. Delivery goes over somebody else's network to
somebody else's server, which is allowed to be slow or gone; the audit hook only
ever puts an entry on a queue, and a full queue is dropped rather than waited
on. A push notification is not worth a stalled RDP handshake.
*/
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
)

// Formats. What the far end expects to receive.
const (
	FormatNtfy    = "ntfy"    // ntfy.sh or a self-hosted instance
	FormatDiscord = "discord" // a channel webhook
	FormatSlack   = "slack"   // an incoming webhook
	FormatJSON    = "json"    // anything else: a plain JSON body
)

type Config struct {
	Enabled bool
	URL     string
	Format  string

	// Events are audit action names. Everything else is ignored, which is the
	// point: the log records far more than anybody wants on their phone.
	Events []string

	Timeout time.Duration
}

// Notifier turns audit entries into messages and delivers them.
//
// One goroutine does the delivering, so events arrive in the order they
// happened and a slow endpoint cannot open a connection per event.
type Notifier struct {
	mu  sync.RWMutex
	cfg Config

	client *http.Client
	queue  chan audit.Entry

	// dropped counts events the queue had no room for, so the next message
	// that does get through can admit to it.
	dropped atomic.Int64

	// sent is for the tests, which need to know delivery finished without
	// sleeping and hoping.
	sent atomic.Int64
}

const queueDepth = 64

func New(cfg Config) *Notifier {
	// The timeout is per request, from the context, rather than on the client:
	// this one is shared with requests already in flight when somebody saves
	// the settings page, and http.Client.Timeout is not safe to write then.
	n := &Notifier{
		queue:  make(chan audit.Entry, queueDepth),
		client: &http.Client{},
	}
	n.Configure(cfg)
	return n
}

// Configure swaps the settings under a running notifier.
//
// The destination is editable in the web interface and takes effect on save:
// waiting for a restart to change where alerts go would mean dropping every
// live desktop session to fix a wrong URL.
func (n *Notifier) Configure(cfg Config) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Format == "" {
		cfg.Format = FormatNtfy
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg
}

func (n *Notifier) config() Config {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cfg
}

// Handle is the audit watcher. It decides whether anybody wants to hear about
// this entry and hands it on; it never blocks and never fails.
func (n *Notifier) Handle(e audit.Entry) {
	cfg := n.config()
	if !cfg.Enabled || cfg.URL == "" || !wanted(cfg.Events, e.Action) {
		return
	}

	select {
	case n.queue <- e:
	default:
		// The endpoint is not keeping up. Losing the event is better than
		// blocking whoever logged it, and the count goes out with the next one.
		n.dropped.Add(1)
	}
}

/*
Run delivers what Handle queued, until the context is cancelled.

The rate limit is the reason this is not just a goroutine per event. A gateway
under a password-guessing run can write lockout entries faster than anyone
wants to read them, and a phone that buzzes forty times stops being a warning
and becomes something you turn off. Five in quick succession get through, then
one every half minute, and the suppressed count rides along with the next
message so the shape of what happened is not lost.
*/
func (n *Notifier) Run(ctx context.Context) {
	const (
		burst   = 5
		refill  = 30 * time.Second
		maxWait = 5 * time.Minute
	)

	tokens := burst
	last := time.Now()
	var suppressed int

	for {
		var e audit.Entry
		select {
		case <-ctx.Done():
			return
		case e = <-n.queue:
		}

		now := time.Now()
		if grown := int(now.Sub(last) / refill); grown > 0 {
			tokens = min(tokens+grown, burst)
			last = last.Add(time.Duration(grown) * refill)
		}
		if tokens == burst {
			// A full bucket accrues nothing, so keep the clock with it. Without
			// this a quiet afternoon would bank hours of credit and let the
			// whole of a password-guessing run through at once.
			last = now
		}
		if tokens == 0 {
			suppressed++
			continue
		}
		tokens--

		m := render(e)
		m.Suppressed = suppressed + int(n.dropped.Swap(0))
		suppressed = 0

		send, cancel := context.WithTimeout(ctx, maxWait)
		err := n.deliver(send, m)
		cancel()

		if err != nil {
			// Worth saying once, at warning level, without the URL: it can
			// carry a token, and a log line is a file somebody else may read.
			slog.Warn("a notification could not be delivered", "event", e.Action, "err", err)
			continue
		}
		n.sent.Add(1)
	}
}

// Test sends a message right now and reports what happened, so the button in
// the settings page can show the real reason instead of "it did not work".
func (n *Notifier) Test(ctx context.Context) error {
	cfg := n.config()
	if cfg.URL == "" {
		return fmt.Errorf("no notification URL is set")
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout+5*time.Second)
	defer cancel()

	return n.deliver(ctx, Message{
		Title: "Revpd test",
		Body:  "Notifications from this gateway arrive here.",
		Event: "test",
	})
}

// deliver posts one message, retrying the failures that are usually somebody
// else's brief problem rather than ours.
func (n *Notifier) deliver(ctx context.Context, m Message) error {
	cfg := n.config()

	var last error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return last
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}

		status, err := n.attempt(ctx, cfg, m)
		switch {
		case err != nil && status == 0:
			last = err
		case err != nil:
			return err // the request itself is wrong; repeating it changes nothing
		case status < 300:
			return nil
		default:
			last = fmt.Errorf("the server answered %d", status)
		}
	}
	return last
}

// attempt is one request. A returned status of zero means it never got an
// answer, which is the case worth trying again; a status with an error beside
// it means the far end objected to the request and always will.
func (n *Notifier) attempt(ctx context.Context, cfg Config, m Message) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := request(ctx, cfg, m)
	if err != nil {
		return -1, err // a broken URL will not fix itself on the second try
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// 401, 404, 400: sending it again would only produce the same answer more
	// often. 5xx and 429 are somebody else's brief problem.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return resp.StatusCode, fmt.Errorf("the server answered %s", resp.Status)
	}
	return resp.StatusCode, nil
}

func wanted(events []string, action string) bool {
	for _, e := range events {
		if e == action {
			return true
		}
	}
	return false
}

package audit_test

import (
	"context"
	"testing"

	"github.com/plattnericus/revpd/internal/audit"
)

func TestWatchersSeeWhatWasWritten(t *testing.T) {
	_, log := newLog(t)

	var seen []audit.Entry
	log.Watch(func(e audit.Entry) { seen = append(seen, e) })

	seed(t, log, 3)

	if len(seen) != 3 {
		t.Fatalf("watcher saw %d entries, want 3", len(seen))
	}
	if seen[0].Action != audit.ActionLoginOK || seen[0].Actor != "felix" {
		t.Errorf("watcher got %+v", seen[0])
	}
	// Appending stamps the time when the caller did not, and a watcher that
	// wants to say when something happened needs that filled in.
	if seen[0].TS.IsZero() {
		t.Error("the entry reached the watcher without a timestamp")
	}
}

// A watcher must not be able to break logging, which is the one thing that has
// to keep working when everything else is going wrong.
func TestAppendSurvivesAWatcherThatMisbehaves(t *testing.T) {
	_, log := newLog(t)

	log.Watch(func(e audit.Entry) {
		// Reentrant: a notifier that logged its own failures would land here.
		if e.Action == audit.ActionLoginOK {
			_ = log.Append(context.Background(), audit.Entry{
				Actor: "watcher", Action: audit.ActionRelayRejected,
			})
		}
	})

	seed(t, log, 1)

	if broken, n, err := log.Verify(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	} else if broken != nil {
		t.Fatalf("the chain broke at %d: %s", broken.ID, broken.Reason)
	} else if n != 2 {
		t.Fatalf("chain has %d entries, want 2", n)
	}
}

func TestKnownActionIsHonest(t *testing.T) {
	for _, a := range audit.Actions() {
		if !audit.KnownAction(a) {
			t.Errorf("%q is listed but not recognised", a)
		}
	}
	if audit.KnownAction("relay.opened") {
		t.Error("a near-miss action name was recognised")
	}
}

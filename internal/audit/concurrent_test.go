package audit_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/store"
)

// twoWriters opens the same database twice, which is what actually happens on
// a running gateway: the service holds it open while `revpd` on the command
// line opens it again to add a user or wake a machine.
func twoWriters(t *testing.T) (*audit.Log, *audit.Log) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	service, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open as the service: %v", err)
	}
	t.Cleanup(func() { service.Close() })

	cli, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open as the command line: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	a, err := audit.New(service.DB)
	if err != nil {
		t.Fatalf("service log: %v", err)
	}
	b, err := audit.New(cli.DB)
	if err != nil {
		t.Fatalf("command line log: %v", err)
	}
	return a, b
}

// Administering a running gateway must not look like tampering afterwards.
func TestCommandLineWritesDoNotBreakTheChain(t *testing.T) {
	service, cli := twoWriters(t)
	ctx := context.Background()

	// The service records an event, someone runs a command, the service
	// records the next one. That last write is where the chain used to fork.
	if err := service.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionLoginOK}); err != nil {
		t.Fatalf("service append: %v", err)
	}
	if err := cli.Append(ctx, audit.Entry{Actor: "cli", Action: audit.ActionUserUpdated}); err != nil {
		t.Fatalf("command line append: %v", err)
	}
	if err := service.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionMFAOK}); err != nil {
		t.Fatalf("service append after the command: %v", err)
	}

	brk, n, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil {
		t.Fatalf("routine administration broke the chain at entry %d: %s", brk.ID, brk.Reason)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}
}

// The same thing under contention, which is where a stale head is most likely.
func TestChainSurvivesTwoWritersAtOnce(t *testing.T) {
	service, cli := twoWriters(t)
	ctx := context.Background()

	const each = 25
	var wg sync.WaitGroup
	errs := make(chan error, 2*each)

	for _, w := range []struct {
		log   *audit.Log
		actor string
	}{{service, "service"}, {cli, "cli"}} {
		wg.Add(1)
		go func(log *audit.Log, actor string) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := log.Append(ctx, audit.Entry{
					Actor:  actor,
					Action: audit.ActionRelayOpen,
					Detail: map[string]any{"seq": i},
				}); err != nil {
					errs <- err
					return
				}
			}
		}(w.log, w.actor)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("append: %v", err)
	}

	brk, n, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil {
		t.Fatalf("chain broken at entry %d: %s", brk.ID, brk.Reason)
	}
	if n != 2*each {
		t.Fatalf("verified %d entries, want %d — writes were lost", n, 2*each)
	}
}

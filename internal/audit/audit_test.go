package audit_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/store"
)

func newLog(t *testing.T) (*store.DB, *audit.Log) {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	return db, log
}

func seed(t *testing.T, log *audit.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := log.Append(context.Background(), audit.Entry{
			Actor:  "felix",
			Action: audit.ActionLoginOK,
			SrcIP:  "203.0.113.7",
			Detail: map[string]any{"seq": i},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestVerifyAcceptsIntactChain(t *testing.T) {
	_, log := newLog(t)
	seed(t, log, 25)

	brk, n, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil {
		t.Fatalf("intact chain reported broken at %d: %s", brk.ID, brk.Reason)
	}
	if n != 25 {
		t.Fatalf("verified %d entries, want 25", n)
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	_, log := newLog(t)

	brk, n, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil || n != 0 {
		t.Fatalf("empty log should verify clean, got break=%v n=%d", brk, n)
	}
}

// Editing a row in place must be caught by the content hash.
func TestVerifyDetectsEditedEntry(t *testing.T) {
	db, log := newLog(t)
	seed(t, log, 10)

	_, err := db.Exec(`UPDATE audit_log SET actor = 'mallory' WHERE id = 5`)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	brk, _, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk == nil {
		t.Fatal("edited entry went undetected")
	}
	if brk.ID != 5 {
		t.Fatalf("break reported at %d, want 5", brk.ID)
	}
}

// Deleting a row breaks the prev_hash link of the row that followed it.
func TestVerifyDetectsDeletedEntry(t *testing.T) {
	db, log := newLog(t)
	seed(t, log, 10)

	if _, err := db.Exec(`DELETE FROM audit_log WHERE id = 4`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	brk, _, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk == nil {
		t.Fatal("deleted entry went undetected")
	}
	if brk.ID != 5 {
		t.Fatalf("break reported at %d, want 5 (the orphaned successor)", brk.ID)
	}
}

// The classic forgery attempt: rewrite the row and recompute its own hash,
// but the successor still points at the old digest.
func TestVerifyDetectsRehashedForgery(t *testing.T) {
	db, log := newLog(t)
	seed(t, log, 6)

	var prev string
	if err := db.QueryRow(`SELECT prev_hash FROM audit_log WHERE id = 3`).Scan(&prev); err != nil {
		t.Fatalf("read prev: %v", err)
	}

	// Forge entry 3 with a hash that is internally consistent.
	_, err := db.Exec(`
		UPDATE audit_log
		SET actor = 'mallory',
		    hash  = lower(hex(randomblob(32)))
		WHERE id = 3`)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	brk, _, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk == nil {
		t.Fatal("rehashed forgery went undetected")
	}
}

// Truncating the tail is the one edit a hash chain alone cannot see, so we at
// least pin the head. This documents that limitation deliberately.
func TestHeadTracksTip(t *testing.T) {
	_, log := newLog(t)
	seed(t, log, 3)

	head := log.Head()
	seed(t, log, 1)

	if log.Head() == head {
		t.Fatal("head did not advance after append")
	}
}

// Two goroutines appending at once must not fork the chain.
func TestConcurrentAppendsKeepChainIntact(t *testing.T) {
	_, log := newLog(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				err := log.Append(context.Background(), audit.Entry{
					Actor:  "felix",
					Action: audit.ActionRelayOpen,
					Detail: map[string]any{"worker": n, "seq": j},
				})
				if err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	brk, n, err := log.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil {
		t.Fatalf("concurrent appends forked the chain at %d: %s", brk.ID, brk.Reason)
	}
	if n != 160 {
		t.Fatalf("verified %d entries, want 160", n)
	}
}

// A restart has to pick the chain up where it left off.
func TestChainSurvivesReopen(t *testing.T) {
	db, log := newLog(t)
	seed(t, log, 5)
	head := log.Head()

	reopened, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.Head() != head {
		t.Fatalf("head after reopen = %s, want %s", reopened.Head(), head)
	}

	seed(t, reopened, 5)

	brk, n, err := reopened.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if brk != nil {
		t.Fatalf("chain broken across reopen at %d: %s", brk.ID, brk.Reason)
	}
	if n != 10 {
		t.Fatalf("verified %d entries, want 10", n)
	}
}

func TestListFiltersByAction(t *testing.T) {
	_, log := newLog(t)
	ctx := context.Background()

	seed(t, log, 3)
	err := log.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionWolSent, Object: "pc-buero"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := log.List(ctx, audit.Query{Action: audit.ActionWolSent})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Object != "pc-buero" {
		t.Fatalf("object = %q, want pc-buero", got[0].Object)
	}
}

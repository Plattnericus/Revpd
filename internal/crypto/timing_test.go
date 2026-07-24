package crypto_test

import (
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/crypto"
)

// SpendVerifyTime is only useful if it actually does the Argon2 work. A
// malformed dummy hash would make it return instantly, which would hand an
// attacker a timing oracle for which usernames exist.
func TestSpendVerifyTimeIsRealWork(t *testing.T) {
	// Baseline: a genuine verification against a real hash.
	real, err := crypto.HashPassword("some-real-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	measure := func(f func()) time.Duration {
		// Warm up so the first allocation does not skew the reading.
		f()
		start := time.Now()
		for i := 0; i < 3; i++ {
			f()
		}
		return time.Since(start) / 3
	}

	genuine := measure(func() { crypto.VerifyPassword("wrong-password", real) })
	dummy := measure(func() { crypto.SpendVerifyTime("wrong-password") })

	if genuine < time.Millisecond {
		t.Fatalf("a real verification took %v — Argon2 is not doing any work", genuine)
	}

	// They will never be identical, but they must be the same order of
	// magnitude. A dummy that bails out early would be orders faster.
	ratio := float64(genuine) / float64(dummy)
	if ratio > 3 || ratio < 0.33 {
		t.Fatalf("dummy takes %v but a real check takes %v (ratio %.1f) — "+
			"the timing defence is not working", dummy, genuine, ratio)
	}
}

// Whatever it is given, it must never report success.
func TestSpendVerifyTimeNeverSucceeds(t *testing.T) {
	for _, pw := range []string{"", "password", "admin", "correct horse battery staple"} {
		// The function has no return value on purpose; this documents that it
		// is a cost, not a check. If someone ever gives it one, this fails.
		crypto.SpendVerifyTime(pw)
	}
}

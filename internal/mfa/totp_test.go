package mfa_test

import (
	"errors"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/pquerna/otp/totp"
)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return c
}

func enroll(t *testing.T) string {
	t.Helper()
	secret, uri, err := mfa.TOTP{Skew: 1}.Enroll("revpd", "felix")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if uri == "" {
		t.Fatal("enroll returned no otpauth uri")
	}
	return secret
}

func TestVerifyAcceptsCurrentCode(t *testing.T) {
	secret := enroll(t)
	now := time.Now()

	c, err := mfa.TOTP{Skew: 1}.Verify(secret, codeAt(t, secret, now), 0, now)
	if err != nil {
		t.Fatalf("current code rejected: %v", err)
	}
	if want := now.Unix() / mfa.Period; c != want {
		t.Fatalf("counter = %d, want %d", c, want)
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret := enroll(t)

	if _, err := (mfa.TOTP{Skew: 1}).Verify(secret, "000000", 0, time.Now()); !errors.Is(err, mfa.ErrBadCode) {
		t.Fatalf("err = %v, want ErrBadCode", err)
	}
}

// The whole point of the guard: a code that already logged someone in is dead.
func TestVerifyRejectsReplay(t *testing.T) {
	secret := enroll(t)
	now := time.Now()
	code := codeAt(t, secret, now)

	used, err := mfa.TOTP{Skew: 1}.Verify(secret, code, 0, now)
	if err != nil {
		t.Fatalf("first use rejected: %v", err)
	}

	_, err = mfa.TOTP{Skew: 1}.Verify(secret, code, used, now)
	if !errors.Is(err, mfa.ErrReplayed) {
		t.Fatalf("replayed code err = %v, want ErrReplayed", err)
	}
}

// Someone who captures a code cannot walk it backwards either.
func TestVerifyRejectsOlderStepAfterNewerUse(t *testing.T) {
	secret := enroll(t)
	now := time.Now()

	prev := codeAt(t, secret, now.Add(-mfa.Period*time.Second))
	current := codeAt(t, secret, now)
	if prev == current {
		t.Skip("step boundary landed such that both codes match")
	}

	used, err := mfa.TOTP{Skew: 1}.Verify(secret, current, 0, now)
	if err != nil {
		t.Fatalf("current code rejected: %v", err)
	}

	if _, err := (mfa.TOTP{Skew: 1}).Verify(secret, prev, used, now); !errors.Is(err, mfa.ErrReplayed) {
		t.Fatalf("older step err = %v, want ErrReplayed", err)
	}
}

func TestSkewWindow(t *testing.T) {
	secret := enroll(t)
	now := time.Now()

	cases := []struct {
		name   string
		offset time.Duration
		skew   uint
		ok     bool
	}{
		{"one step early, skew 1", -mfa.Period * time.Second, 1, true},
		{"one step late, skew 1", +mfa.Period * time.Second, 1, true},
		{"two steps early, skew 1", -2 * mfa.Period * time.Second, 1, false},
		{"two steps late, skew 1", +2 * mfa.Period * time.Second, 1, false},
		{"one step early, skew 0", -mfa.Period * time.Second, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := codeAt(t, secret, now.Add(tc.offset))

			_, err := mfa.TOTP{Skew: tc.skew}.Verify(secret, code, 0, now)
			if tc.ok && err != nil {
				t.Fatalf("code within window rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("code outside window accepted")
			}
		})
	}
}

func TestSecretFromURI(t *testing.T) {
	secret, uri, err := mfa.TOTP{}.Enroll("revpd", "felix")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	got, err := mfa.SecretFromURI(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	if got != secret {
		t.Fatalf("secret from uri = %q, want %q", got, secret)
	}
}

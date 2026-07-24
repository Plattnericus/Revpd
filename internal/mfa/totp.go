// Package mfa holds the second-factor verifiers.
package mfa

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrBadCode  = errors.New("code is not valid")
	ErrReplayed = errors.New("code was already used")
)

// Period is the TOTP step. 30s is what every authenticator app assumes.
const Period = 30

// TOTP verifies time-based codes and refuses to accept the same step twice.
//
// The replay guard matters more than it looks: with skew enabled a code stays
// valid for 90 seconds, which is plenty of time for someone watching a shoulder
// or a proxy to reuse it.
type TOTP struct {
	Skew uint // extra steps accepted on each side, 1 = ±30s
}

// Enroll builds a new secret plus the otpauth:// URI for the QR code.
func (t TOTP) Enroll(issuer, account string) (secret string, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      Period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // SHA1 is what the apps actually support
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Verify checks the code and returns the step it matched.
//
// lastCounter is the step this user most recently burned; the caller must
// persist the returned counter before treating the login as successful.
func (t TOTP) Verify(secret, code string, lastCounter int64, now time.Time) (counter int64, err error) {
	step := now.Unix() / Period

	// Walk the window newest-first so a fresh code costs the fewest comparisons.
	for _, off := range window(t.Skew) {
		c := step + off

		ok, err := totp.ValidateCustom(code, secret, time.Unix(c*Period, 0), totp.ValidateOpts{
			Period:    Period,
			Skew:      0, // we do the windowing ourselves so we learn which step hit
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil || !ok {
			continue
		}

		// Same step or older means it is a replay, even though the maths check out.
		if c <= lastCounter {
			return 0, ErrReplayed
		}
		return c, nil
	}
	return 0, ErrBadCode
}

// window returns step offsets ordered 0, -1, +1, -2, +2 ...
func window(skew uint) []int64 {
	out := []int64{0}
	for i := int64(1); i <= int64(skew); i++ {
		out = append(out, -i, i)
	}
	return out
}

// SecretFromURI pulls the raw secret back out of an otpauth:// URI.
func SecretFromURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse otpauth uri: %w", err)
	}
	s := u.Query().Get("secret")
	if s == "" {
		return "", errors.New("otpauth uri has no secret")
	}
	return s, nil
}

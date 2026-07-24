package crypto_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/plattnericus/revpd/internal/crypto"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := crypto.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := crypto.VerifyPassword("correct horse battery staple", h); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := crypto.VerifyPassword("wrong", h); !errors.Is(err, crypto.ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch", err)
	}
}

// A shared salt would let one rainbow table cover every account.
func TestHashesAreSalted(t *testing.T) {
	a, _ := crypto.HashPassword("same")
	b, _ := crypto.HashPassword("same")
	if a == b {
		t.Fatal("identical passwords produced identical hashes")
	}
}

func TestHashCarriesItsParameters(t *testing.T) {
	h, _ := crypto.HashPassword("x")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected hash format: %s", h)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$argon2id$", "$bcrypt$v=19$m=1,t=1,p=1$aaaa$bbbb",
		"$argon2id$v=99$m=65536,t=3,p=4$aaaa$bbbb",
	} {
		if err := crypto.VerifyPassword("x", bad); !errors.Is(err, crypto.ErrInvalidHash) {
			t.Errorf("VerifyPassword(%q) err = %v, want ErrInvalidHash", bad, err)
		}
	}
}

func TestSealRoundTrip(t *testing.T) {
	key, err := crypto.NewMasterKey()
	if err != nil {
		t.Fatalf("new key: %v", err)
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}

	sealed, err := s.Seal("totp:7", []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(string(sealed), "JBSWY3DPEHPK3PXP") {
		t.Fatal("plaintext is visible in the ciphertext")
	}

	out, err := s.Open("totp:7", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(out) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("got %q", out)
	}
}

// The label is bound as AAD, so a blob moved between rows must not open.
func TestSealLabelIsBound(t *testing.T) {
	key, _ := crypto.NewMasterKey()
	s, _ := crypto.NewSealer(key)

	sealed, _ := s.Seal("totp:7", []byte("secret"))
	if _, err := s.Open("totp:8", sealed); err == nil {
		t.Fatal("ciphertext opened under a different label")
	}
}

func TestSealDetectsTampering(t *testing.T) {
	key, _ := crypto.NewMasterKey()
	s, _ := crypto.NewSealer(key)

	sealed, _ := s.Seal("duo:skey", []byte("secret"))
	sealed[len(sealed)-1] ^= 0x01

	if _, err := s.Open("duo:skey", sealed); err == nil {
		t.Fatal("flipped bit went undetected")
	}
}

func TestNewSealerRejectsBadKeys(t *testing.T) {
	for _, bad := range []string{"", "zzzz", "abcd", strings.Repeat("ab", 16)} {
		if _, err := crypto.NewSealer(bad); err == nil {
			t.Errorf("NewSealer(%q) accepted a bad key", bad)
		}
	}
}

func TestBackupCodesAreReadable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := crypto.NewBackupCode()
		if err != nil {
			t.Fatalf("new code: %v", err)
		}
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("code %q is not in NNNNN-NNNNN form", c)
		}
		// Characters people misread on paper must not appear.
		if strings.ContainsAny(c, "IO01") {
			t.Fatalf("code %q contains an ambiguous character", c)
		}
		if seen[c] {
			t.Fatalf("duplicate code %q after %d draws", c, i)
		}
		seen[c] = true
	}
}

func TestNormalizeBackupCode(t *testing.T) {
	want := "K7RM29XQPD"
	for _, in := range []string{"K7RM2-9XQPD", "k7rm2-9xqpd", " K7RM2 9XQPD ", "K7RM29XQPD"} {
		if got := crypto.NormalizeBackupCode(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHashTokenIsStable(t *testing.T) {
	tok, err := crypto.RandomToken(32)
	if err != nil {
		t.Fatalf("random token: %v", err)
	}
	if crypto.HashToken(tok) != crypto.HashToken(tok) {
		t.Fatal("HashToken is not deterministic")
	}
	if crypto.HashToken(tok) == tok {
		t.Fatal("HashToken returned the token itself")
	}
}

func TestRandomTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		tok, _ := crypto.RandomToken(32)
		if seen[tok] {
			t.Fatalf("duplicate token after %d draws", i)
		}
		seen[tok] = true
	}
}

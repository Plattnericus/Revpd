// Package crypto wraps the primitives we use so nobody has to pick parameters
// at the call site. Nothing here is homegrown.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. RFC 9106 second recommendation, comfortable on a small VPS.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	ErrInvalidHash = errors.New("malformed password hash")
	ErrMismatch    = errors.New("password does not match")
)

// HashPassword returns a self-describing PHC string, so parameters can be
// raised later without breaking existing hashes.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword re-derives with the stored parameters and compares in constant time.
func VerifyPassword(pw, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidHash
	}
	if version != argon2.Version {
		return fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var mem uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHash
	}

	got := argon2.IDKey([]byte(pw), salt, time, mem, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// dummyHash is a real Argon2id hash of a value nobody knows.
//
// It exists so that logging in as an account that does not exist costs the
// same as getting the password wrong. That only holds if the hash actually
// parses — a malformed one would make VerifyPassword bail out immediately and
// hand an attacker a timing oracle for free. TestDummyHashIsRealWork pins it.
var dummyHash string

func init() {
	// Derived once at startup from a random value, so it is guaranteed valid
	// and no attacker can precompute against a constant baked into the binary.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("crypto: cannot seed the timing dummy: " + err.Error())
	}
	h, err := HashPassword(string(secret))
	if err != nil {
		panic("crypto: cannot build the timing dummy: " + err.Error())
	}
	dummyHash = h
}

// SpendVerifyTime does the same work a real password check would, and always
// fails. Call it on the paths where no account was found, so the response time
// does not reveal which usernames exist.
func SpendVerifyTime(password string) {
	_ = VerifyPassword(password, dummyHash)
}

// Sealer encrypts secrets at rest: TOTP seeds, Duo keys, anything in `settings`.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer takes the 32-byte master key, hex-encoded.
func NewSealer(hexKey string) (*Sealer, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("master key is not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (64 hex chars), got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns nonce||ciphertext. The label is bound as additional data, so a
// ciphertext copied from one column into another fails to open.
func (s *Sealer) Seal(label string, plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(label)), nil
}

func (s *Sealer) Open(label string, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(label))
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", label, err)
	}
	return plain, nil
}

// NewMasterKey mints a key for `revpd init`.
func NewMasterKey() (string, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	return hex.EncodeToString(k), nil
}

// RandomToken returns a URL-safe token with n bytes of entropy.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is for values we only ever compare, never display again: session
// cookies and grant tokens. They already carry full entropy, so a plain SHA-256
// is right here — Argon2 would only slow down every single request.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqualString avoids leaking a match through timing.
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var backupAlphabet = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)

// NewBackupCode returns a 10-character code in two groups, e.g. "K7RM2-9XQPD".
// The alphabet drops I, O, 0 and 1 because people read these off paper.
func NewBackupCode() (string, error) {
	b := make([]byte, 7)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read backup code: %w", err)
	}
	s := backupAlphabet.EncodeToString(b)[:10]
	return s[:5] + "-" + s[5:], nil
}

// NormalizeBackupCode lets people type it lowercase, spaced, or without the dash.
func NormalizeBackupCode(s string) string {
	r := strings.NewReplacer("-", "", " ", "", "\t", "")
	return strings.ToUpper(r.Replace(s))
}

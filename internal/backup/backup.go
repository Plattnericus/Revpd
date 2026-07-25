// Package backup writes and reads a single encrypted file holding everything a
// Revpd installation needs to be recreated somewhere else.
//
// That is deliberately all three pieces: the database, the master key and the
// configuration. The database alone is useless — every TOTP seed inside it is
// encrypted with the master key — so a backup that left the key out would
// restore into an installation nobody could log into.
//
// Because the file carries the master key, it is encrypted with a passphrase
// the operator chooses. A plaintext archive holding that key would be worse
// than no backup at all.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

// Extension is what a backup file is called. Distinctive enough that restore
// can tell someone they picked the wrong file before asking for a passphrase.
const Extension = ".revpd-backup"

var (
	ErrNotABackup   = errors.New("this is not a Revpd backup file")
	ErrWrongVersion = errors.New("this backup was written by a newer Revpd")
	ErrPassphrase   = errors.New("wrong passphrase, or the file is damaged")
)

// magic marks our files. The version byte lets a future format change be
// refused clearly instead of failing as a decryption error.
var magic = [8]byte{'R', 'E', 'V', 'P', 'D', 'B', 'A', 'K'}

const formatVersion = 1

// Argon2id parameters for turning the passphrase into a key. Heavier than the
// login hash on purpose: a backup file may sit on a USB stick for years, and
// unlocking it happens once, so a second of work is cheap.
const (
	kdfTime    = 4
	kdfMemory  = 128 * 1024 // KiB
	kdfThreads = 4
	kdfKeyLen  = 32
	saltLen    = 16
)

// Contents is what a backup holds, in memory.
type Contents struct {
	// Database is a consistent snapshot, produced with VACUUM INTO.
	Database []byte

	// Env is the file holding REVPD_MASTER_KEY.
	Env []byte

	// Config is revpd.yaml.
	Config []byte

	// Created and Hostname are for the operator, so a folder full of backups
	// can be told apart without unpacking them.
	Created  time.Time
	Hostname string
	Version  string
}

/* --------------------------------------------------------------- write --- */

// Write encrypts the contents and writes them to w.
//
// Layout: magic, version, salt, nonce, then AES-256-GCM over a gzipped tar.
// The header travels in the clear because restore has to recognise the file
// before it can ask for a passphrase; it is authenticated as additional data
// so it cannot be edited without breaking the seal.
func Write(w io.Writer, c Contents, passphrase string) error {
	if passphrase == "" {
		return errors.New("a passphrase is required")
	}

	archive, err := pack(c)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("read salt: %w", err)
	}

	header := buildHeader(salt, c.Created)

	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonce, archive, header)

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write backup header: %w", err)
	}
	if _, err := w.Write(nonce); err != nil {
		return fmt.Errorf("write backup nonce: %w", err)
	}
	if _, err := w.Write(sealed); err != nil {
		return fmt.Errorf("write backup body: %w", err)
	}
	return nil
}

// WriteFile writes a backup with permissions that keep it private.
func WriteFile(path string, c Contents, passphrase string) error {
	// Check before creating anything. Otherwise a refusal still leaves an
	// empty file sitting there looking like a backup.
	if passphrase == "" {
		return errors.New("a passphrase is required")
	}

	// Build the whole thing in memory first, so a failure halfway through
	// cannot leave a truncated file that restore would accept the header of.
	var buf bytes.Buffer
	if err := Write(&buf, c, passphrase); err != nil {
		return err
	}

	// 0600 from the start: the file holds the master key, so it must never be
	// briefly world-readable between creation and a later chmod.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(buf.Bytes()); err != nil {
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Sync()
}

const headerLen = 8 + 1 + saltLen + 8 // magic, version, salt, unix seconds

func buildHeader(salt []byte, created time.Time) []byte {
	h := make([]byte, 0, headerLen)
	h = append(h, magic[:]...)
	h = append(h, formatVersion)
	h = append(h, salt...)

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(created.Unix()))
	return append(h, ts...)
}

/* ---------------------------------------------------------------- read --- */

// Peek reads just the header, so a caller can confirm the file is a backup and
// show when it was made before asking for a passphrase.
func Peek(r io.Reader) (created time.Time, err error) {
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return time.Time{}, ErrNotABackup
	}

	if !bytes.Equal(header[:8], magic[:]) {
		return time.Time{}, ErrNotABackup
	}
	if header[8] > formatVersion {
		return time.Time{}, ErrWrongVersion
	}
	return time.Unix(int64(binary.BigEndian.Uint64(header[headerLen-8:])), 0), nil
}

// Read decrypts a backup.
func Read(r io.Reader, passphrase string) (*Contents, error) {
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, ErrNotABackup
	}
	if !bytes.Equal(header[:8], magic[:]) {
		return nil, ErrNotABackup
	}
	if header[8] > formatVersion {
		return nil, ErrWrongVersion
	}
	salt := header[9 : 9+saltLen]

	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, ErrNotABackup
	}

	// Bounded so a corrupt or hostile file cannot exhaust memory. A real
	// backup is a few hundred kilobytes.
	sealed, err := io.ReadAll(io.LimitReader(r, 512<<20))
	if err != nil {
		return nil, fmt.Errorf("read backup body: %w", err)
	}

	archive, err := aead.Open(nil, nonce, sealed, header)
	if err != nil {
		// A wrong passphrase and a damaged file are indistinguishable here,
		// and saying so plainly is more useful than a cryptographic error.
		return nil, ErrPassphrase
	}
	return unpack(archive)
}

// ReadFile is Read against a path.
func ReadFile(path, passphrase string) (*Contents, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	return Read(f, passphrase)
}

// PeekFile reports when a backup was made, without needing the passphrase.
func PeekFile(path string) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	return Peek(f)
}

func newAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(passphrase), salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	return cipher.NewGCM(block)
}

/* ------------------------------------------------------------ archiving --- */

// Names inside the archive. Stable, because a future version has to be able to
// read what this one wrote.
const (
	nameDatabase = "revpd.db"
	nameEnv      = "env"
	nameConfig   = "revpd.yaml"
	nameMeta     = "meta"
)

func pack(c Contents) ([]byte, error) {
	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	meta := fmt.Sprintf("hostname=%s\nversion=%s\ncreated=%s\n",
		c.Hostname, c.Version, c.Created.UTC().Format(time.RFC3339))

	entries := []struct {
		name string
		body []byte
	}{
		{nameMeta, []byte(meta)},
		{nameDatabase, c.Database},
		{nameEnv, c.Env},
		{nameConfig, c.Config},
	}

	for _, e := range entries {
		if len(e.body) == 0 && e.name != nameConfig {
			continue
		}
		hdr := &tar.Header{
			Name:    e.name,
			Mode:    0o600,
			Size:    int64(len(e.body)),
			ModTime: c.Created,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write %s header: %w", e.name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, fmt.Errorf("write %s: %w", e.name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close archive: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close compressor: %w", err)
	}
	return buf.Bytes(), nil
}

func unpack(archive []byte) (*Contents, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("read compressed archive: %w", err)
	}
	defer zr.Close()

	out := &Contents{}
	tr := tar.NewReader(zr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}

		// Entry sizes are bounded so a crafted archive cannot blow up memory
		// after decryption succeeded.
		body, err := io.ReadAll(io.LimitReader(tr, 512<<20))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}

		switch hdr.Name {
		case nameDatabase:
			out.Database = body
		case nameEnv:
			out.Env = body
		case nameConfig:
			out.Config = body
		case nameMeta:
			parseMeta(string(body), out)
		}
	}

	if len(out.Database) == 0 {
		return nil, errors.New("the backup contains no database")
	}
	return out, nil
}

func parseMeta(s string, out *Contents) {
	for _, line := range splitLines(s) {
		key, value, ok := cut(line, '=')
		if !ok {
			continue
		}
		switch key {
		case "hostname":
			out.Hostname = value
		case "version":
			out.Version = value
		case "created":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				out.Created = t
			}
		}
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

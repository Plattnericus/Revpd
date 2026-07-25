package backup_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/backup"
)

func sample() backup.Contents {
	return backup.Contents{
		Database: []byte("SQLite format 3\x00 pretend this is a database"),
		Env:      []byte("REVPD_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"),
		Config:   []byte("data_dir: /var/lib/revpd\nweb:\n  hostname: gw.example.com\n"),
		Created:  time.Now().Truncate(time.Second),
		Hostname: "gw.example.com",
		Version:  "v1.0.0",
	}
}

func TestRoundTrip(t *testing.T) {
	in := sample()

	var buf bytes.Buffer
	if err := backup.Write(&buf, in, "a good passphrase"); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := backup.Read(&buf, "a good passphrase")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(out.Database, in.Database) {
		t.Fatal("the database did not survive the round trip")
	}
	if !bytes.Equal(out.Env, in.Env) {
		t.Fatal("the master key did not survive the round trip")
	}
	if !bytes.Equal(out.Config, in.Config) {
		t.Fatal("the config did not survive the round trip")
	}
	if out.Hostname != in.Hostname || out.Version != in.Version {
		t.Fatalf("metadata lost: %q %q", out.Hostname, out.Version)
	}
}

// The master key is in there, so nothing may be readable in the file.
func TestFileRevealsNothing(t *testing.T) {
	in := sample()

	var buf bytes.Buffer
	if err := backup.Write(&buf, in, "a good passphrase"); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw := buf.String()

	for _, secret := range []string{
		"0123456789abcdef0123456789abcdef",
		"REVPD_MASTER_KEY",
		"gw.example.com",
		"SQLite format",
	} {
		if strings.Contains(raw, secret) {
			t.Fatalf("the backup file contains %q in the clear", secret)
		}
	}
}

func TestWrongPassphraseIsRefused(t *testing.T) {
	var buf bytes.Buffer
	if err := backup.Write(&buf, sample(), "the right one"); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := backup.Read(bytes.NewReader(buf.Bytes()), "the wrong one")
	if !errors.Is(err, backup.ErrPassphrase) {
		t.Fatalf("err = %v, want ErrPassphrase", err)
	}
}

// Someone points restore at a photo. Say so, do not ask for a passphrase first.
func TestOtherFilesAreRecognised(t *testing.T) {
	for _, junk := range [][]byte{
		nil,
		[]byte("hello"),
		[]byte("\x89PNG\r\n\x1a\n"),
		bytes.Repeat([]byte{0}, 200),
	} {
		if _, err := backup.Read(bytes.NewReader(junk), "x"); !errors.Is(err, backup.ErrNotABackup) {
			t.Errorf("err = %v, want ErrNotABackup", err)
		}
		if _, err := backup.Peek(bytes.NewReader(junk)); !errors.Is(err, backup.ErrNotABackup) {
			t.Errorf("peek err = %v, want ErrNotABackup", err)
		}
	}
}

// A backup from a future version must be refused clearly, not as a crypto error.
func TestNewerFormatIsRefused(t *testing.T) {
	var buf bytes.Buffer
	backup.Write(&buf, sample(), "pw")

	raw := buf.Bytes()
	raw[8] = 99 // bump the version byte

	if _, err := backup.Read(bytes.NewReader(raw), "pw"); !errors.Is(err, backup.ErrWrongVersion) {
		t.Fatalf("err = %v, want ErrWrongVersion", err)
	}
}

// The header is authenticated, so editing it must break the seal rather than
// letting someone pass off a backup as older or from another host.
func TestTamperedHeaderIsDetected(t *testing.T) {
	var buf bytes.Buffer
	backup.Write(&buf, sample(), "pw")

	raw := buf.Bytes()
	raw[len(raw)-1] ^= 0x01 // flip a bit in the ciphertext

	if _, err := backup.Read(bytes.NewReader(raw), "pw"); err == nil {
		t.Fatal("a flipped bit went undetected")
	}

	// And a rewritten timestamp in the plaintext header.
	var buf2 bytes.Buffer
	backup.Write(&buf2, sample(), "pw")
	raw2 := buf2.Bytes()
	raw2[headerTimestampOffset] ^= 0xFF

	if _, err := backup.Read(bytes.NewReader(raw2), "pw"); err == nil {
		t.Fatal("an edited header went undetected")
	}
}

// magic(8) + version(1) + salt(16), so the timestamp starts here.
const headerTimestampOffset = 8 + 1 + 16

// Peek has to work without the passphrase, so a menu can list backups.
func TestPeekShowsTheDateWithoutTheKey(t *testing.T) {
	in := sample()

	var buf bytes.Buffer
	if err := backup.Write(&buf, in, "pw"); err != nil {
		t.Fatalf("write: %v", err)
	}

	created, err := backup.Peek(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !created.Equal(in.Created) {
		t.Fatalf("peek returned %v, want %v", created, in.Created)
	}
}

func TestWriteFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test"+backup.Extension)

	if err := backup.WriteFile(path, sample(), "pw"); err != nil {
		t.Fatalf("write file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Windows does not model unix permissions, so only assert where it means
	// something.
	if info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("backup is readable by others: %v", info.Mode().Perm())
	}

	out, err := backup.ReadFile(path, "pw")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(out.Database, sample().Database) {
		t.Fatal("round trip through a file lost the database")
	}
}

// A failed write must not leave a truncated file that looks like a backup.
func TestFailedWriteLeavesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken"+backup.Extension)

	err := backup.WriteFile(path, sample(), "")
	if err == nil {
		t.Fatal("an empty passphrase was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a file was left behind after a failed write")
	}
}

func TestBackupWithoutADatabaseIsRefused(t *testing.T) {
	c := sample()
	c.Database = nil

	var buf bytes.Buffer
	if err := backup.Write(&buf, c, "pw"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := backup.Read(bytes.NewReader(buf.Bytes()), "pw"); err == nil {
		t.Fatal("a backup with no database was accepted")
	}
}

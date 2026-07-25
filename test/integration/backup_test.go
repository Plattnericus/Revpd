//go:build integration

// Backup and restore against a real database: the thing that has to work when
// someone moves a gateway to new hardware, and the thing nobody finds out is
// broken until the day they need it.
package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/backup"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

// populated returns a database with the kind of content a real one holds.
func populated(t *testing.T, dir string) (*store.DB, string, string) {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(dir, "revpd.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	key, _ := crypto.NewMasterKey()
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	hash, _ := crypto.HashPassword("CorrectHorseBatteryStaple")
	uid, err := db.CreateUser(ctx, store.User{
		Username: "felix", DisplayName: "Felix", PasswordHash: hash, Role: "admin", RDPHint: "felix",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret, _, _ := mfa.TOTP{Skew: 1}.Enroll("revpd", "felix")
	enc, _ := sealer.Seal(fmt.Sprintf("totp:%d", uid), []byte(secret))
	db.SetTOTPSecret(ctx, uid, enc)

	tid, err := db.CreateTarget(ctx, store.Target{
		Name: "Büro-PC", IP: "192.168.1.40", MAC: "a8:a1:59:3c:d2:11",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	db.GrantTargetAccess(ctx, uid, tid)

	log.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionLoginOK, SrcIP: "203.0.113.9"})
	log.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionWolSent, Object: "Büro-PC"})

	return db, key, secret
}

// The whole point: back up here, restore somewhere else, and the second
// factors still work — which they only can if the master key travelled too.
func TestBackupRestoreToAnotherMachine(t *testing.T) {
	ctx := context.Background()

	// ── the original machine ────────────────────────────────────────────
	srcDir := t.TempDir()
	db, masterKey, secret := populated(t, srcDir)

	snapshot := filepath.Join(srcDir, "snapshot.db")
	if err := db.BackupTo(ctx, snapshot); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	dbBytes, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	db.Close()

	env := []byte("REVPD_MASTER_KEY=" + masterKey + "\n")
	cfg := []byte("data_dir: /var/lib/revpd\nweb:\n  hostname: gw.example.com\n")

	backupPath := filepath.Join(t.TempDir(), "moving-day"+backup.Extension)
	err = backup.WriteFile(backupPath, backup.Contents{
		Database: dbBytes, Env: env, Config: cfg,
		Created: time.Now(), Hostname: "old-server", Version: "test",
	}, "the backup passphrase")
	if err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// ── the new machine, nothing on it ──────────────────────────────────
	dstDir := t.TempDir()

	c, err := backup.ReadFile(backupPath, "the backup passphrase")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}

	restored := filepath.Join(dstDir, "revpd.db")
	if err := os.WriteFile(restored, c.Database, 0o600); err != nil {
		t.Fatalf("restore database: %v", err)
	}

	db2, err := store.Open(ctx, restored)
	if err != nil {
		t.Fatalf("open restored database: %v", err)
	}
	defer db2.Close()

	// ── everything has to be there ──────────────────────────────────────
	users, err := db2.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 || users[0].Username != "felix" {
		t.Fatalf("restored %d users: %+v", len(users), users)
	}
	if users[0].Role != "admin" {
		t.Fatalf("felix came back as %q, not admin", users[0].Role)
	}

	targets, _ := db2.ListTargets(ctx)
	if len(targets) != 1 || targets[0].Name != "Büro-PC" {
		t.Fatalf("restored %d machines: %+v", len(targets), targets)
	}
	if targets[0].MAC != "a8:a1:59:3c:d2:11" {
		t.Fatalf("the MAC did not survive: %q", targets[0].MAC)
	}

	// Access must still be granted, or people find themselves locked out of
	// their own machines after a restore.
	if ok, err := db2.CanReach(ctx, &users[0], targets[0].ID); err != nil || !ok {
		t.Fatal("the restored user cannot reach the restored machine")
	}

	// ── and the second factor still works ───────────────────────────────
	//
	// This is what proves the master key travelled: the TOTP seed is encrypted
	// with it, so without the key this fails.
	keyFromBackup := parseEnvKey(t, c.Env)
	sealer, err := crypto.NewSealer(keyFromBackup)
	if err != nil {
		t.Fatalf("sealer from restored key: %v", err)
	}

	plain, err := sealer.Open(fmt.Sprintf("totp:%d", users[0].ID), users[0].TOTPSecretEnc)
	if err != nil {
		t.Fatalf("could not decrypt the restored TOTP seed: %v", err)
	}
	if string(plain) != secret {
		t.Fatal("the restored TOTP seed does not match the original")
	}

	code, _ := totp.GenerateCode(string(plain), time.Now())
	if _, err := (mfa.TOTP{Skew: 1}).Verify(string(plain), code, 0, time.Now()); err != nil {
		t.Fatalf("a code from the restored secret was refused: %v", err)
	}

	// ── the audit trail must still verify ───────────────────────────────
	log2, err := audit.New(db2.DB)
	if err != nil {
		t.Fatalf("audit on restored database: %v", err)
	}
	brk, n, err := log2.Verify(ctx)
	if err != nil || brk != nil {
		t.Fatalf("the restored audit chain is broken: %v %v", brk, err)
	}
	if n < 2 {
		t.Fatalf("the restored audit trail has %d entries, expected the originals", n)
	}

	// And the config came along.
	if !bytes.Contains(c.Config, []byte("gw.example.com")) {
		t.Fatal("the configuration did not survive")
	}
}

// A snapshot taken while the database is in use must still be readable — the
// reason for VACUUM INTO rather than copying the file.
func TestSnapshotIsConsistentUnderWrites(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	db, _, _ := populated(t, dir)
	defer db.Close()

	// Keep writing while the snapshot is taken.
	done := make(chan struct{})
	go func() {
		defer close(done)
		log, _ := audit.New(db.DB)
		for i := 0; i < 50; i++ {
			log.Append(ctx, audit.Entry{Actor: "felix", Action: audit.ActionRelayOpen})
		}
	}()

	snapshot := filepath.Join(dir, "busy.db")
	if err := db.BackupTo(ctx, snapshot); err != nil {
		t.Fatalf("snapshot while writing: %v", err)
	}
	<-done

	// The snapshot has to open, and its chain has to verify.
	db2, err := store.Open(ctx, snapshot)
	if err != nil {
		t.Fatalf("the snapshot does not open: %v", err)
	}
	defer db2.Close()

	log2, err := audit.New(db2.DB)
	if err != nil {
		t.Fatalf("audit on snapshot: %v", err)
	}
	if brk, _, err := log2.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("the snapshot's audit chain is broken: %v %v", brk, err)
	}
}

// Deleting an account must take everything attached to it, or a removed user
// leaves grants and passkeys behind that still work.
func TestDeleteUserTakesEverything(t *testing.T) {
	ctx := context.Background()
	db, _, _ := populated(t, t.TempDir())
	defer db.Close()

	u, err := db.UserByName(ctx, "felix")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	targets, _ := db.ListTargets(ctx)

	// Give them the full set of attachments.
	hash, _ := crypto.HashPassword("AAAAABBBBB")
	db.Exec(`INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)`, u.ID, hash)
	db.AddPasskey(ctx, store.Passkey{
		UserID: u.ID, CredentialID: []byte("cred"), PublicKey: []byte("key"), Name: "YubiKey",
	})
	db.CreateGrant(ctx, store.Grant{
		UserID: u.ID, TargetID: targets[0].ID, SrcIP: "203.0.113.9", Mode: "portal",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}, "hash")

	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	for _, check := range []struct {
		table string
		query string
	}{
		{"backup_codes", `SELECT count(*) FROM backup_codes WHERE user_id = ?`},
		{"webauthn_creds", `SELECT count(*) FROM webauthn_creds WHERE user_id = ?`},
		{"user_targets", `SELECT count(*) FROM user_targets WHERE user_id = ?`},
		{"grants", `SELECT count(*) FROM grants WHERE user_id = ?`},
		{"sessions", `SELECT count(*) FROM sessions WHERE user_id = ?`},
	} {
		var n int
		if err := db.QueryRow(check.query, u.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", check.table, err)
		}
		if n != 0 {
			t.Errorf("%d rows left behind in %s", n, check.table)
		}
	}

	// The audit trail keeps its history on purpose.
	log, _ := audit.New(db.DB)
	if _, n, _ := log.Verify(ctx); n == 0 {
		t.Error("deleting a user wiped the audit trail")
	}
}

// Removing a machine must not erase the record that sessions to it happened.
func TestDeleteTargetKeepsHistory(t *testing.T) {
	ctx := context.Background()
	db, _, _ := populated(t, t.TempDir())
	defer db.Close()

	targets, _ := db.ListTargets(ctx)
	id := targets[0].ID

	u, err := db.UserByName(ctx, "felix")
	if err != nil {
		t.Fatalf("user: %v", err)
	}

	// A session belongs to a grant, so make a real one rather than passing a
	// zero id the foreign key would reject.
	grantID, err := db.CreateGrant(ctx, store.Grant{
		UserID: u.ID, TargetID: id, SrcIP: "203.0.113.9", Mode: "portal",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}, "hash")
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}

	sessionID, err := db.OpenRDPSession(ctx, grantID, id, "203.0.113.9")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	db.CloseRDPSession(ctx, sessionID, 100, 200, "done")

	if err := db.DeleteTarget(ctx, id); err != nil {
		t.Fatalf("delete target: %v", err)
	}

	var n int
	db.QueryRow(`SELECT count(*) FROM user_targets WHERE target_id = ?`, id).Scan(&n)
	if n != 0 {
		t.Errorf("%d access grants left behind", n)
	}

	// The session row survives with a null target.
	var sessions int
	db.QueryRow(`SELECT count(*) FROM rdp_sessions WHERE id = ?`, sessionID).Scan(&sessions)
	if sessions != 1 {
		t.Error("removing a machine deleted the record of past sessions")
	}
}

func TestDeleteMissingIsAnError(t *testing.T) {
	ctx := context.Background()
	db, _, _ := populated(t, t.TempDir())
	defer db.Close()

	if err := db.DeleteUser(ctx, 9999); err == nil {
		t.Error("deleting a user that does not exist reported success")
	}
	if err := db.DeleteTarget(ctx, 9999); err == nil {
		t.Error("deleting a machine that does not exist reported success")
	}
}

func parseEnvKey(t *testing.T, env []byte) string {
	t.Helper()

	const prefix = "REVPD_MASTER_KEY="
	for _, line := range bytes.Split(env, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(prefix)) {
			return string(bytes.TrimSpace(line[len(prefix):]))
		}
	}
	t.Fatal("the backup env holds no master key")
	return ""
}

package store

import (
	"context"
	"fmt"
	"time"
)

// Passkey is one registered WebAuthn credential.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Name         string
	CreatedAt    time.Time
}

func (db *DB) AddPasskey(ctx context.Context, p Passkey) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO webauthn_creds (user_id, credential_id, public_key, sign_count, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.UserID, p.CredentialID, p.PublicKey, p.SignCount, p.Name, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("store passkey: %w", err)
	}
	return res.LastInsertId()
}

// PasskeysFor returns everything registered to an account.
//
// Reads fully and closes before returning: the pool holds a single connection,
// so a caller that writes while a query is still streaming would deadlock
// against itself.
func (db *DB) PasskeysFor(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, name, created_at
		 FROM webauthn_creds WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()

	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var created int64
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.SignCount, &p.Name, &created); err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		p.CreatedAt = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PasskeyByCredentialID finds a credential regardless of who owns it, which is
// what a usernameless login needs.
func (db *DB) PasskeyByCredentialID(ctx context.Context, credID []byte) (*Passkey, error) {
	var p Passkey
	var created int64

	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, name, created_at
		 FROM webauthn_creds WHERE credential_id = ?`, credID).
		Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.SignCount, &p.Name, &created)
	if err != nil {
		return nil, ErrNotFound
	}

	p.CreatedAt = time.Unix(created, 0)
	return &p, nil
}

// UpdateSignCount records the authenticator's counter after a successful login.
//
// The counter only ever moves forward. A value that does not advance can mean
// a cloned authenticator, so the caller is expected to check before storing.
func (db *DB) UpdateSignCount(ctx context.Context, id int64, count uint32) error {
	_, err := db.ExecContext(ctx,
		`UPDATE webauthn_creds SET sign_count = ? WHERE id = ?`, count, id)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	return nil
}

func (db *DB) DeletePasskey(ctx context.Context, userID, id int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM webauthn_creds WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	return nil
}

func (db *DB) CountPasskeys(ctx context.Context, userID int64) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_creds WHERE user_id = ?`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count passkeys: %w", err)
	}
	return n, nil
}

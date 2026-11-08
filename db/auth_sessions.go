package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrAuthCredentialsChanged also covers an old process trying to use a signing
// key after rotation. The caller must authenticate again; it must not retry with
// the new credential generation using an already-verified old password.
var ErrAuthCredentialsChanged = errors.New("authentication credentials changed")

// CheckOrInitializeAuthSigningKey is the only startup path. Once initialized, a
// different file key must be activated by the explicit maintenance command. An
// old instance restarting cannot reactivate a compromised key after rotation.
func (d *DB) CheckOrInitializeAuthSigningKey(ctx context.Context, keyHash string) error {
	if _, err := d.ExecContext(ctx, `INSERT INTO auth_state(singleton, signing_key_hash)
VALUES (true, $1) ON CONFLICT (singleton) DO NOTHING`, keyHash); err != nil {
		return err
	}
	var current string
	if err := d.QueryRowContext(ctx, `SELECT signing_key_hash FROM auth_state WHERE singleton`).Scan(&current); err != nil {
		return err
	}
	if current != keyHash {
		return ErrAuthCredentialsChanged
	}
	return nil
}

// ActivateAuthSigningKey is an explicit, offline maintenance operation. It is
// never called automatically by the server. Changing the key invalidates every
// issued session, including sessions on an older still-running instance.
func (d *DB) ActivateAuthSigningKey(ctx context.Context, keyHash string) error {
	return d.activateAuthSigningKey(ctx, keyHash, false)
}

// RotateAuthSigningKey is the explicit maintenance command's atomic operation.
// Even re-activating the same file revokes every existing session.
func (d *DB) RotateAuthSigningKey(ctx context.Context, keyHash string) error {
	return d.activateAuthSigningKey(ctx, keyHash, true)
}

func (d *DB) activateAuthSigningKey(ctx context.Context, keyHash string, revokeAll bool) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_state(singleton, signing_key_hash)
VALUES (true, $1) ON CONFLICT (singleton) DO NOTHING`, keyHash); err != nil {
		return err
	}
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT signing_key_hash FROM auth_state WHERE singleton FOR UPDATE`).Scan(&current); err != nil {
		return err
	}
	if current != keyHash || revokeAll {
		if _, err = tx.ExecContext(ctx, `UPDATE auth_state SET signing_key_hash=$1, generation=gen_random_uuid() WHERE singleton`, keyHash); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= now()
OR generation <> (SELECT generation FROM auth_state WHERE singleton)`); err != nil {
		return err
	}
	return tx.Commit()
}

// IssueAuthSession binds the exact token to the password that was verified. The
// row locks use the same order as the password-change trigger: password, state,
// sessions. Thus a login racing password reset either commits before reset (and
// is revoked by it), or fails its password comparison. It cannot mint a session
// in the new generation with an old password.
func (d *DB) IssueAuthSession(ctx context.Context, tokenHash, keyHash, verifiedPasswordHash string, expires time.Time) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentPassword string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='auth.password_hash' FOR SHARE`).Scan(&currentPassword)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthCredentialsChanged
	}
	if err != nil {
		return err
	}
	if currentPassword == "" || currentPassword != verifiedPasswordHash {
		return ErrAuthCredentialsChanged
	}
	var currentKey, generation string
	err = tx.QueryRowContext(ctx, `SELECT signing_key_hash, generation::text FROM auth_state WHERE singleton FOR UPDATE`).Scan(&currentKey, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthCredentialsChanged
	}
	if err != nil {
		return err
	}
	if currentKey != keyHash {
		return ErrAuthCredentialsChanged
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= now()`); err != nil {
		return err
	}
	// Bound stored sessions without allowing anonymous requests to evict them.
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE token_hash IN
(SELECT token_hash FROM auth_sessions ORDER BY created_at DESC, token_hash OFFSET 99)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions(token_hash, generation, expires_at) VALUES ($1, $2::uuid, $3)`, tokenHash, generation, expires); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) AuthSessionActive(ctx context.Context, tokenHash, keyHash string) (bool, error) {
	var active bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM auth_sessions AS session JOIN auth_state AS state ON session.generation=state.generation
WHERE state.singleton AND state.signing_key_hash=$1 AND session.token_hash=$2 AND session.expires_at > now())`, keyHash, tokenHash).Scan(&active)
	return active, err
}

func (d *DB) RevokeAuthSession(ctx context.Context, tokenHash string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM auth_sessions WHERE token_hash=$1`, tokenHash)
	return err
}

// ChangeAuthPassword is a compare-and-swap. The database trigger revokes all
// sessions in this same transaction, and also protects offline password resets.
func (d *DB) ChangeAuthPassword(ctx context.Context, verifiedHash, nextHash string) error {
	res, err := d.ExecContext(ctx, `UPDATE settings SET value=$1, updated_at=now() WHERE key='auth.password_hash' AND value=$2`, nextHash, verifiedHash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAuthCredentialsChanged
	}
	return nil
}

func (d *DB) RevokeAllAuthSessions(ctx context.Context) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE auth_state SET generation=gen_random_uuid() WHERE singleton`); err != nil {
		return fmt.Errorf("rotate authentication generation: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions`); err != nil {
		return err
	}
	return tx.Commit()
}

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func maintenancePaths(t *testing.T) (string, string, string, []string) {
	t.Helper()
	keyParent := t.TempDir()
	if err := os.Chmod(keyParent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(keyParent, "jwt.key.next")
	data, skills := t.TempDir(), t.TempDir()
	return keyFile, data, skills, []string{"--key-file", keyFile, "--data-dir", data, "--skills-dir", skills}
}

func TestAuthSessionMaintenancePrepareIsPrivateAndExplicit(t *testing.T) {
	keyFile, _, _, args := maintenancePaths(t)
	var out, errOut bytes.Buffer
	command := append([]string{"prepare-key"}, args...)
	if code := run(command, &out, &errOut); code != 0 {
		t.Fatalf("validate exit=%d error=%s", code, errOut.String())
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("validation created a key")
	}
	if code := run(append(command, "--apply"), &out, &errOut); code != 0 {
		t.Fatalf("prepare exit=%d error=%s", code, errOut.String())
	}
	key, err := readKey(keyFile)
	if err != nil || len(key) != 64 {
		t.Fatalf("new key failed validation: %v", err)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions=%o", info.Mode().Perm())
	}
	if strings.Contains(out.String()+errOut.String(), string(key)) {
		t.Fatal("maintenance output exposed the key")
	}
	if code := run(append(command, "--apply"), &out, &errOut); code == 0 {
		t.Fatal("prepare overwrote an existing key")
	}
	after, err := readKey(keyFile)
	if err != nil || !bytes.Equal(key, after) {
		t.Fatal("rejected prepare changed existing bytes")
	}
}

func TestAuthSessionMaintenanceRejectsBrowsableKeyPaths(t *testing.T) {
	keyFile, data, skills, _ := maintenancePaths(t)
	for _, root := range []string{data, skills} {
		if err := validateKeyPath(filepath.Join(root, "jwt.key"), data, skills); err == nil {
			t.Fatal("browsable root accepted for signing key")
		}
		alias := filepath.Join(filepath.Dir(keyFile), "alias")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		if err := validateKeyPath(filepath.Join(alias, "jwt.key"), data, skills); err == nil {
			t.Fatal("symlink into browsable root accepted for signing key")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("synthetic", 8)), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := keyFile + ".alias"
	if err := os.Symlink(keyFile, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(alias); err == nil {
		t.Fatal("key file symlink accepted")
	}
}

func TestAuthSessionMaintenancePasswordInputIsBounded(t *testing.T) {
	for _, value := range []string{"short", strings.Repeat("x", 8192), strings.Repeat("界", 25), string([]byte{0xff, 0xfe})} {
		reader := strings.NewReader(value)
		var out, errOut bytes.Buffer
		if code := runWithInput([]string{"reset-password", "--database", "test", "--password-stdin", "--apply"}, reader, &out, &errOut); code == 0 {
			t.Fatal("invalid password was accepted")
		}
		if reader.Size()-int64(reader.Len()) > 73 {
			t.Fatal("password input was not bounded")
		}
		if strings.Contains(out.String()+errOut.String(), value) {
			t.Fatal("invalid password was echoed")
		}
	}
}

func TestAuthSessionMaintenanceActivation(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required; CI rejects skipped security tests")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || !strings.Contains(u.Path, "test") {
		t.Fatal("security tests require an explicit loopback test database")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("could not open isolated test database")
	}
	t.Cleanup(func() { _ = admin.Close() })
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(entropy[:8])
	role, database := "artex_ops_test_"+suffix, "artex_ops_test_"+suffix
	password := hex.EncodeToString(entropy[:])
	roleSQL, dbSQL := pgx.Identifier{role}.Sanitize(), pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s'`, roleSQL, password)); err != nil {
		t.Fatal("could not create isolated maintenance test role")
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + dbSQL + ` WITH (FORCE)`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + roleSQL)
	})
	if _, err := admin.Exec(`CREATE DATABASE ` + dbSQL + ` OWNER ` + roleSQL); err != nil {
		t.Fatal("could not create isolated maintenance test database")
	}
	u.User, u.Path = url.UserPassword(role, password), "/"+database
	t.Setenv("ARTEX_PG_DSN", u.String())
	store, err := db.Open(u.String())
	if err != nil {
		t.Fatal("could not initialize isolated maintenance schema")
	}
	t.Cleanup(func() { _ = store.Close() })
	oldKey, tokenHash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := store.CheckOrInitializeAuthSigningKey(t.Context(), oldKey); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("auth.password_hash", "synthetic-maintenance-password"); err != nil {
		t.Fatal(err)
	}
	if err := store.IssueAuthSession(t.Context(), tokenHash, oldKey, "synthetic-maintenance-password", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	keyFile, _, _, args := maintenancePaths(t)
	if err := prepareKey(keyFile, true); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	command := append(append([]string{"activate-key"}, args...), "--database", database)
	if code := run(command, &out, &errOut); code != 0 {
		t.Fatalf("validate exit=%d error=%s", code, errOut.String())
	}
	if active, err := store.AuthSessionActive(t.Context(), tokenHash, oldKey); err != nil || !active {
		t.Fatal("validation revoked sessions")
	}
	wrongTarget := append(append([]string{"activate-key"}, args...), "--database", database+"_wrong", "--apply")
	if code := run(wrongTarget, &out, &errOut); code == 0 {
		t.Fatal("wrong expected database was modified")
	}
	if code := run(append(command, "--apply"), &out, &errOut); code != 0 {
		t.Fatalf("activate exit=%d error=%s", code, errOut.String())
	}
	if active, err := store.AuthSessionActive(t.Context(), tokenHash, oldKey); err != nil || active {
		t.Fatal("explicit rotation retained an old session")
	}
	key, err := readKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(key)
	if err := store.CheckOrInitializeAuthSigningKey(t.Context(), hex.EncodeToString(digest[:])); err != nil {
		t.Fatal("intended key was not activated")
	}
	if strings.Contains(out.String()+errOut.String(), string(key)) || strings.Contains(out.String()+errOut.String(), password) || strings.Contains(out.String()+errOut.String(), u.String()) {
		t.Fatal("maintenance output leaked private configuration")
	}
	// Same-key activation is still a full revocation, in one transaction.
	newKeyHash := hex.EncodeToString(digest[:])
	if err := store.IssueAuthSession(t.Context(), tokenHash, newKeyHash, "synthetic-maintenance-password", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if code := run(append(command, "--apply"), &out, &errOut); code != 0 {
		t.Fatal("same-key explicit activation failed")
	}
	if active, err := store.AuthSessionActive(t.Context(), tokenHash, newKeyHash); err != nil || active {
		t.Fatal("same-key maintenance retained a session")
	}
	if err := store.IssueAuthSession(t.Context(), tokenHash, newKeyHash, "synthetic-maintenance-password", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	reset := []string{"reset-password", "--database", database, "--password-stdin"}
	const newPassword = "synthetic-maintenance-reset-password"
	if code := runWithInput(reset, strings.NewReader(newPassword), &out, &errOut); code != 0 {
		t.Fatalf("password validation exit=%d error=%s", code, errOut.String())
	}
	if active, err := store.AuthSessionActive(t.Context(), tokenHash, newKeyHash); err != nil || !active {
		t.Fatal("password validation changed sessions")
	}
	if code := runWithInput(append(reset, "--apply"), strings.NewReader(newPassword), &out, &errOut); code != 0 {
		t.Fatalf("password reset exit=%d error=%s", code, errOut.String())
	}
	if active, err := store.AuthSessionActive(t.Context(), tokenHash, newKeyHash); err != nil || active {
		t.Fatal("password reset retained a session")
	}
	hash, _, err := store.GetSetting("auth.password_hash")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) != nil {
		t.Fatal("reset did not persist a valid bcrypt hash")
	}
	if strings.Contains(out.String()+errOut.String(), newPassword) {
		t.Fatal("reset output exposed the password")
	}
}

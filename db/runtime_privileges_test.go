package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This is an actual new database owned by a temporary non-superuser, rather
// than a mocked privilege query. It exercises the same Open/DDL/seed path used
// at every application startup. The fixture permits only loopback test DSNs.
func TestAuthSessionLeastPrivilegeRuntime(t *testing.T) {
	admin, _, _ := authDBFixture(t)
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(entropy[:8])
	role := "artex_app_test_" + suffix
	database := "artex_runtime_test_" + suffix
	password := hex.EncodeToString(entropy[:]) // Synthetic, unique to this disposable DB.
	roleSQL := pgx.Identifier{role}.Sanitize()
	dbSQL := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s'`, roleSQL, password)); err != nil {
		t.Fatal("test administrator could not create the isolated runtime role")
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + dbSQL + ` WITH (FORCE)`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + roleSQL)
	})
	if _, err := admin.Exec(`CREATE DATABASE ` + dbSQL + ` OWNER ` + roleSQL); err != nil {
		t.Fatal("test administrator could not create the isolated runtime database")
	}
	u, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil {
		t.Fatal("invalid isolated test DSN")
	}
	u.Path = "/" + database
	u.User = url.UserPassword(role, password)
	if err := CheckRuntimeDSN(t.Context(), u.String()); err != nil {
		t.Fatalf("non-privileged application role rejected: %v", err)
	}
	app, err := Open(u.String())
	if err != nil {
		t.Fatal("non-privileged application role could not run schema/seed")
	}
	t.Cleanup(func() { _ = app.Close() })
	keyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokenHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := app.CheckOrInitializeAuthSigningKey(t.Context(), keyHash); err != nil {
		t.Fatal(err)
	}
	if err := app.SetSetting("auth.password_hash", "synthetic-runtime-password-hash"); err != nil {
		t.Fatal(err)
	}
	if err := app.IssueAuthSession(t.Context(), tokenHash, keyHash, "synthetic-runtime-password-hash", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if active, err := app.AuthSessionActive(t.Context(), tokenHash, keyHash); err != nil || !active {
		t.Fatalf("runtime role session path failed: active=%v err=%v", active, err)
	}
	if err := CheckRuntimeDSN(t.Context(), os.Getenv("ARTEX_PG_DSN")); !errors.Is(err, ErrUnsafeRuntimeRole) {
		t.Fatalf("test administrator was accepted as a runtime identity: %v", err)
	}
	// NOINHERIT is not a boundary: membership can still confer SET ROLE.
	for _, dangerous := range []string{"pg_read_server_files", "pg_write_server_files", "pg_execute_server_program"} {
		if _, err := admin.Exec(`GRANT ` + dangerous + ` TO ` + roleSQL); err != nil {
			t.Fatal(err)
		}
		if err := CheckRuntimeDSN(t.Context(), u.String()); !errors.Is(err, ErrUnsafeRuntimeRole) {
			t.Fatalf("runtime membership in %s was accepted: %v", dangerous, err)
		}
		if _, err := admin.Exec(`REVOKE ` + dangerous + ` FROM ` + roleSQL); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckRuntimeDSN(t.Context(), u.String()); err != nil {
		t.Fatalf("revoked server privileges were not recognized: %v", err)
	}
}

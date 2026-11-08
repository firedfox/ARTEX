package db

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func authDBFixture(t *testing.T) (*DB, string, string) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required; CI rejects skipped security tests")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || !strings.Contains(u.Path, "test") {
		t.Fatal("security tests require an explicit loopback test database")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("configured security database unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	key := strings.Repeat("a", 64)
	password := "synthetic-password-hash"
	if err := d.ActivateAuthSigningKey(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeAllAuthSessions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("auth.password_hash", password); err != nil {
		t.Fatal(err)
	}
	return d, key, password
}

func TestAuthSessionConcurrentIssuanceStaysBounded(t *testing.T) {
	d, key, password := authDBFixture(t)
	errorsOut := make(chan error, 120)
	var wg sync.WaitGroup
	for i := 0; i < 120; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			digest := sha256.Sum256([]byte(fmt.Sprintf("synthetic-session-%d", i)))
			errorsOut <- d.IssueAuthSession(t.Context(), hex.EncodeToString(digest[:]), key, password, time.Now().Add(time.Hour))
		}(i)
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM auth_sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 100 {
		t.Fatalf("concurrent session cap=%d want 100", count)
	}
}

func TestAuthSessionPasswordTriggerCoversOfflineReset(t *testing.T) {
	d, key, password := authDBFixture(t)
	token := strings.Repeat("b", 64)
	if err := d.IssueAuthSession(t.Context(), token, key, password, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("auth.password_hash", password); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("non_auth_security_test_setting", "changed"); err != nil {
		t.Fatal(err)
	}
	active, err := d.AuthSessionActive(t.Context(), token, key)
	if err != nil || !active {
		t.Fatalf("unchanged password/unrelated setting revoked session: active=%v err=%v", active, err)
	}
	if _, err := d.Exec(`UPDATE settings SET value='synthetic-replaced-hash' WHERE key='auth.password_hash'`); err != nil {
		t.Fatal(err)
	}
	active, err = d.AuthSessionActive(t.Context(), token, key)
	if err != nil || active {
		t.Fatalf("offline password reset kept session: active=%v err=%v", active, err)
	}
	if err := d.IssueAuthSession(t.Context(), strings.Repeat("c", 64), key, password, time.Now().Add(time.Hour)); !errors.Is(err, ErrAuthCredentialsChanged) {
		t.Fatalf("stale password was re-bound to new generation: %v", err)
	}
}

func TestAuthSessionStartupKeyMismatchIsReadOnly(t *testing.T) {
	d, key, password := authDBFixture(t)
	token := strings.Repeat("d", 64)
	if err := d.IssueAuthSession(t.Context(), token, key, password, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("e", 64)
	if err := d.CheckOrInitializeAuthSigningKey(t.Context(), other); !errors.Is(err, ErrAuthCredentialsChanged) {
		t.Fatalf("unexpected startup mismatch result: %v", err)
	}
	active, err := d.AuthSessionActive(t.Context(), token, key)
	if err != nil || !active {
		t.Fatalf("rejected startup changed current sessions: active=%v err=%v", active, err)
	}
	if err := d.ActivateAuthSigningKey(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckOrInitializeAuthSigningKey(t.Context(), key); !errors.Is(err, ErrAuthCredentialsChanged) {
		t.Fatalf("old key reactivated on restart: %v", err)
	}
	active, err = d.AuthSessionActive(t.Context(), token, key)
	if err != nil || active {
		t.Fatalf("rotated key retained session: active=%v err=%v", active, err)
	}
}

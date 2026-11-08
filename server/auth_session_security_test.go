package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const authSessionTestPassword = "synthetic-current-password"

func authSessionFixture(t *testing.T) (*Server, string) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required; CI rejects skipped security tests")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || !strings.Contains(u.Path, "test") {
		t.Fatal("security tests require an explicit loopback test database")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("configured security database unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m, jwtKey: []byte("synthetic-session-signing-key-32-bytes"), loginLimit: newLoginLimiter(time.Now)}
	if err := m.pg.ActivateAuthSigningKey(t.Context(), tokenDigest(string(s.jwtKey))); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.RevokeAllAuthSessions(t.Context()); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(authSessionTestPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	return s, string(hash)
}

func authSessionRequest(s *Server, token, method, path, body string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.requireAuth(handler).ServeHTTP(w, r)
	return w
}

func assertAuthSession(t *testing.T, s *Server, token string, want int) {
	t.Helper()
	w := authSessionRequest(s, token, "GET", "/api/workspace/list", "", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	if w.Code != want {
		t.Fatalf("authentication status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}

func TestAuthSessionRejectsSignedButUnissuedTokens(t *testing.T) {
	s, _ := authSessionFixture(t)
	// This has the correct current key and every required claim, but no login.
	forged, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, forged, 401)
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "ARTEX", IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
	}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, legacy, 401)
	for _, path := range []string{"/api/auth/not-public", "/api/auth/change-password", "/api/auth/logout"} {
		w := authSessionRequest(s, "", "POST", path, "{}", func(w http.ResponseWriter, _ *http.Request) {
			t.Error("private auth-prefix handler reached")
			w.WriteHeader(204)
		})
		if w.Code != 401 {
			t.Fatalf("%s: status=%d", path, w.Code)
		}
	}
}

func TestAuthSessionLoginAndSetupActuallyRegisterTokens(t *testing.T) {
	s, _ := authSessionFixture(t)
	loginBody, _ := json.Marshal(map[string]string{"password": authSessionTestPassword})
	w := authSessionRequest(s, "", "POST", "/api/auth/login", string(loginBody), s.authLogin)
	if w.Code != http.StatusOK {
		t.Fatalf("real login status=%d body=%s", w.Code, w.Body.String())
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Token == "" {
		t.Fatal("real login did not return a token")
	}
	assertAuthSession(t, s, result.Token, http.StatusNoContent)
	loginToken := result.Token
	if _, err := s.m.pg.Exec(`DELETE FROM settings WHERE key='auth.password_hash'`); err != nil {
		t.Fatal(err)
	}
	s.setupToken = "synthetic-private-setup-token"
	setupBody, _ := json.Marshal(map[string]string{"password": "synthetic-setup-password", "setup_token": s.setupToken})
	w = authSessionRequest(s, "", "POST", "/api/auth/init", string(setupBody), s.authInit)
	if w.Code != http.StatusOK {
		t.Fatalf("real setup status=%d body=%s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Token == "" {
		t.Fatal("real setup did not return a token")
	}
	assertAuthSession(t, s, result.Token, http.StatusNoContent)
	assertAuthSession(t, s, loginToken, http.StatusUnauthorized)
	if s.setupToken != "" {
		t.Fatal("setup token remained active")
	}
}

func TestAuthSessionPersistsAndBindsExactToken(t *testing.T) {
	s, hash := authSessionFixture(t)
	first, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("separate logins must have unpredictable distinct IDs")
	}
	assertAuthSession(t, s, first, 204)
	assertAuthSession(t, s, second, 204)
	// Restart with the same key checks state but does not revoke sessions.
	if err := s.m.pg.CheckOrInitializeAuthSigningKey(t.Context(), tokenDigest(string(s.jwtKey))); err != nil {
		t.Fatal(err)
	}
	restarted := &Server{m: s.m, jwtKey: append([]byte{}, s.jwtKey...)}
	assertAuthSession(t, restarted, first, 204)
	var persisted string
	if err := s.m.pg.QueryRow(`SELECT token_hash FROM auth_sessions WHERE token_hash=$1`, tokenDigest(first)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted == first || len(persisted) != 64 {
		t.Fatal("session store must contain only a SHA-256 digest")
	}
	for _, mutate := range []func(*jwt.RegisteredClaims){
		func(c *jwt.RegisteredClaims) { c.ID = strings.Repeat("ab", 32) },
		func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(c.ExpiresAt.Add(-time.Minute)) },
	} {
		claims, err := parseJWT(first, s.jwtKey)
		if err != nil {
			t.Fatal(err)
		}
		mutate(claims)
		changed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtKey)
		if err != nil {
			t.Fatal(err)
		}
		assertAuthSession(t, s, changed, 401)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/health", nil)
	r.Header.Set("Authorization", "Bearer "+first)
	s.health(w, r)
	if !strings.Contains(w.Body.String(), `"service":"artex"`) {
		t.Fatalf("issued session health=%s", w.Body.String())
	}
}

func TestAuthSessionStrictClaims(t *testing.T) {
	key := []byte("synthetic-session-signing-key-32-bytes")
	token, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*jwt.RegisteredClaims){
		"missing expiry":      func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil },
		"missing issued time": func(c *jwt.RegisteredClaims) { c.IssuedAt = nil },
		"future issued time":  func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"wrong subject":       func(c *jwt.RegisteredClaims) { c.Subject = "another-admin" },
		"wrong issuer":        func(c *jwt.RegisteredClaims) { c.Issuer = "other" },
		"wrong audience":      func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"other"} },
		"missing ID":          func(c *jwt.RegisteredClaims) { c.ID = "" },
		"expired":             func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) },
		"extended lifetime":   func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := parseJWT(token, key)
			if err != nil {
				t.Fatal(err)
			}
			mutate(c)
			bad, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseJWT(bad, key); err == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
	c, _ := parseJWT(token, key)
	bad, err := jwt.NewWithClaims(jwt.SigningMethodHS384, c).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseJWT(bad, key); err == nil {
		t.Fatal("HS384 accepted instead of HS256")
	}
}

func TestAuthSessionLogoutAndPasswordChangeRevoke(t *testing.T) {
	s, hash := authSessionFixture(t)
	first, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	w := authSessionRequest(s, first, "POST", "/api/auth/logout", "", s.authLogout)
	if w.Code != 200 {
		t.Fatalf("logout=%d", w.Code)
	}
	assertAuthSession(t, s, first, 401)
	assertAuthSession(t, s, second, 204)
	body, _ := json.Marshal(map[string]string{"old_password": authSessionTestPassword, "new_password": "synthetic-next-password"})
	w = authSessionRequest(s, second, "POST", "/api/auth/change-password", string(body), s.authChangePassword)
	if w.Code != 200 {
		t.Fatalf("change password=%d body=%s", w.Code, w.Body.String())
	}
	assertAuthSession(t, s, second, 401)
	if _, err := s.issueJWT(t.Context(), hash); !errors.Is(err, db.ErrAuthCredentialsChanged) {
		t.Fatalf("stale verified hash: %v", err)
	}
	nextHash, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(nextHash), []byte("synthetic-next-password")); err != nil {
		t.Fatal(err)
	}
	next, err := s.issueJWT(t.Context(), nextHash)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, next, 204)
}

func TestAuthSessionKeyRotationRejectsOldInstances(t *testing.T) {
	s, hash := authSessionFixture(t)
	token, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	newKey := []byte("synthetic-rotated-signing-key-32-bytes")
	newFingerprint := tokenDigest(string(newKey))
	if err := s.m.pg.ActivateAuthSigningKey(t.Context(), newFingerprint); err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, token, 401)
	if _, err := s.issueJWT(t.Context(), hash); !errors.Is(err, db.ErrAuthCredentialsChanged) {
		t.Fatalf("old process issued session: %v", err)
	}
	if err := s.m.pg.CheckOrInitializeAuthSigningKey(t.Context(), tokenDigest(string(s.jwtKey))); !errors.Is(err, db.ErrAuthCredentialsChanged) {
		t.Fatalf("old key restart accepted: %v", err)
	}
	var current string
	if err := s.m.pg.QueryRow(`SELECT signing_key_hash FROM auth_state WHERE singleton`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != newFingerprint {
		t.Fatal("old startup reactivated an old key")
	}
	next := &Server{m: s.m, jwtKey: newKey}
	fresh, err := next.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, next, fresh, 204)
}

func TestAuthSessionDatabaseFailureIsClosed(t *testing.T) {
	s, hash := authSessionFixture(t)
	token, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, token, 503)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/health", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	s.health(w, r)
	if strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("health leaked identity on DB failure: %s", w.Body.String())
	}
}

func TestAuthSessionPasswordResetRaceRejectsPreviouslyVerifiedHash(t *testing.T) {
	s, oldHash := authSessionFixture(t)
	nextHash, err := bcrypt.GenerateFromPassword([]byte("synthetic-next-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.m.pg.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(t.Context(), `UPDATE settings SET value=$1 WHERE key=$2`, string(nextHash), authPassKey); err != nil {
		t.Fatal(err)
	}
	// The reset is uncommitted while a login that already checked oldHash tries
	// to issue. It must wait for that row, then reject the now-stale password.
	done := make(chan error, 1)
	go func() { _, err := s.issueJWT(context.Background(), oldHash); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("issuance did not wait for password reset: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, db.ErrAuthCredentialsChanged) {
			t.Fatalf("stale login accepted after reset: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login/reset deadlock")
	}
	var count int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM auth_sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale login created %d sessions", count)
	}
}

func TestAuthSessionExpiryCheckedByStore(t *testing.T) {
	s, hash := authSessionFixture(t)
	token, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE auth_sessions SET created_at=now()-interval '2 days', expires_at=now()-interval '1 second' WHERE token_hash=$1`, tokenDigest(token)); err != nil {
		t.Fatal(err)
	}
	assertAuthSession(t, s, token, 401)
}

func TestAuthSessionAuthenticationBodyIsBounded(t *testing.T) {
	for _, which := range []string{"init", "login", "change-password"} {
		t.Run(which, func(t *testing.T) {
			s, hash := authSessionFixture(t)
			token, err := s.issueJWT(t.Context(), hash)
			if err != nil {
				t.Fatal(err)
			}
			handler := s.authLogin
			if which == "init" {
				if _, err := s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey); err != nil {
					t.Fatal(err)
				}
				handler = s.authInit
			} else if which == "change-password" {
				handler = s.authChangePassword
			}
			body := `{"username":"ARTEX","password":"` + strings.Repeat("x", 9<<10) + `","old_password":"` + authSessionTestPassword + `","new_password":"synthetic-next-password"}`
			w := authSessionRequest(s, token, "POST", "/api/auth/"+which, body, handler)
			if w.Code != 413 {
				t.Fatalf("oversized %s status=%d body=%s", which, w.Code, w.Body.String())
			}
			current, _, err := s.m.pg.GetSetting(authPassKey)
			if err != nil {
				t.Fatal(err)
			}
			if (which == "init" && current != "") || (which != "init" && current != hash) {
				t.Fatal("oversized authentication request changed the password")
			}
		})
	}
}

func TestAuthSessionKeyLocationRejectsWorkspaceAndSymlinks(t *testing.T) {
	data := t.TempDir()
	for _, keyDir := range []string{data, filepath.Join(data, "keys")} {
		if _, err := loadOrCreateJWTKey(keyDir, data); err == nil {
			t.Fatalf("workspace key dir accepted: %s", keyDir)
		}
	}
	skills := t.TempDir()
	if _, err := loadOrCreateJWTKey(filepath.Join(skills, "keys"), data, skills); err == nil {
		t.Fatal("skills root accepted for signing key")
	}
	alias := filepath.Join(t.TempDir(), "workspace-alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateJWTKey(filepath.Join(alias, "keys"), data); err == nil {
		t.Fatal("symlinked parent placed signing key in the workspace")
	}
	keyDir := t.TempDir()
	actual := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(actual, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, filepath.Join(keyDir, jwtKeyFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateJWTKey(keyDir, data); err == nil {
		t.Fatal("symlink signing key accepted")
	}
}

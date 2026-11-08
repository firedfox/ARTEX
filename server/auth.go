package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 12 * time.Hour
	jwtIssuer      = "artex"
	jwtAudience    = "artex-console"
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// The lower bound matches the setup page's frontend validation — validation that
	// lives only in the frontend is as good as none: hitting the API directly bypasses
	// it. The upper bound is bcrypt's hard limit: past 72 bytes GenerateFromPassword returns ErrPasswordTooLong; rejecting early beats a cryptic "password encryption failed".
	// Both apply to new passwords only (init, change-password); login never checks
	// length, so passwords set under the old 8-character minimum still log in.
	minPasswordRunes = 12
	maxPasswordBytes = 72
)

// errDataSourceUnavailable is the uniform reply when a password-related read fails.
// These handlers must never mistake a failed read for "not set": authInit once let an
// unauthenticated request through on a database error, overwriting the admin password.
const errDataSourceUnavailable = "Data source temporarily unavailable, please retry later"

// validatePassword returns an empty string when passing, otherwise a reason ready to show the user.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// jwtLegacyBaseDir is the second legacy key location (the executable's directory,
// where releases before ARTEX_JWT_KEY_DIR wrote the key). A var so tests can point it
// at a temp dir.
var jwtLegacyBaseDir = config.BaseDir

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// ARTEX_JWT_KEY_DIR (the /app/keys volume in Docker) or the project base dir, NOT
// the browsable workspace root (dataDir) — the signing key must never be
// listable/downloadable via the file manager. When keyDir/jwt.key is missing, a key
// at dataDir/jwt.key, then at BaseDir()/jwt.key, is migrated and the old file
// removed. Legacy stateless tokens still become invalid: they have no issued
// session record. A normal restart preserves already-recorded sessions. An
// existing key file is never silently overwritten.
func loadOrCreateJWTKey(keyDir, dataDir string, additionalRoots ...string) ([]byte, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create jwt key dir: %w", err)
	}
	if err := validateJWTKeyLocation(keyDir, dataDir); err != nil {
		return nil, err
	}
	for _, root := range additionalRoots {
		if strings.TrimSpace(root) != "" {
			if err := validateJWTKeyLocation(keyDir, root); err != nil {
				return nil, fmt.Errorf("JWT key must be outside every browsable root: %w", err)
			}
		}
	}
	path := filepath.Join(keyDir, jwtKeyFilename)
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() || fi.Size() > 4096 {
			return nil, errors.New("JWT key must be a bounded regular file, not a symlink")
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("JWT key permissions must be 0600")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect jwt key: %w", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := migrateJWTKey(path, dataDir); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if len(key) < 32 {
			return nil, fmt.Errorf("jwt key %s is shorter than 32 bytes; fix or remove it (it is never overwritten)", path)
		}
		return []byte(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read jwt key: %w", err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := writeNewJWTKey(path, buf); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

func validateJWTKeyLocation(keyDir, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	key, err := filepath.EvalSymlinks(keyDir)
	if err != nil {
		return err
	}
	data, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return err
	}
	key, err = filepath.Abs(key)
	if err != nil {
		return err
	}
	data, err = filepath.Abs(data)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(data, key)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("JWT key directory must be outside the browsable workspace, including resolved symlinks")
	}
	return nil
}

// migrateJWTKey copies the first legacy key found (dataDir, then BaseDir) to dst
// and removes the old file. Candidates equal to dst are skipped.
func migrateJWTKey(dst, dataDir string) error {
	for _, src := range []string{
		filepath.Join(dataDir, jwtKeyFilename),
		filepath.Join(jwtLegacyBaseDir(), jwtKeyFilename),
	} {
		if samePath(src, dst) {
			continue
		}
		if fi, err := os.Lstat(src); err == nil && (!fi.Mode().IsRegular() || fi.Size() > 4096) {
			return errors.New("legacy JWT key must be a bounded regular file, not a symlink")
		}
		data, err := os.ReadFile(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Printf("[auth] cannot read legacy JWT key %s: %v", src, err)
			continue
		}
		if err := writeNewJWTKey(dst, data); err != nil {
			return fmt.Errorf("migrate jwt key from %s: %w", src, err)
		}
		if err := os.Remove(src); err != nil {
			log.Printf("[auth] JWT key copied to %s but the old file %s could not be removed: %v", dst, src, err)
		}
		log.Printf("[auth] JWT key migrated from %s to %s", src, dst)
		return nil
	}
	return nil
}

// writeNewJWTKey creates path with mode 0600, failing if it already exists.
func writeNewJWTKey(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func samePath(a, b string) bool {
	if absA, err := filepath.Abs(a); err == nil {
		a = absA
	}
	if absB, err := filepath.Abs(b); err == nil {
		b = absB
	}
	return a == b
}

// signJWT only signs. Such a token is NOT authenticated until issueJWT records
// its exact hash after a successful password check. Keep the two steps explicit:
// possession of even the current signing key must not grant an admin session.
func signJWT(key []byte) (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        hex.EncodeToString(id[:]),
		Issuer:    jwtIssuer,
		Audience:  jwt.ClaimStrings{jwtAudience},
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
	}).SignedString(key)
}

func tokenDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func parseJWT(tokenStr string, key []byte) (*jwt.RegisteredClaims, error) {
	if len(tokenStr) == 0 || len(tokenStr) > 8192 {
		return nil, errors.New("invalid token length")
	}
	claims := &jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(jwtIssuer), jwt.WithAudience(jwtAudience),
		jwt.WithSubject("ARTEX"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || t == nil || !t.Valid {
		return nil, errors.New("invalid token")
	}
	id, idErr := hex.DecodeString(claims.ID)
	if idErr != nil || len(id) != 32 || claims.IssuedAt == nil || claims.ExpiresAt == nil ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > jwtTTL {
		return nil, errors.New("invalid session claims")
	}
	return claims, nil
}

func (s *Server) issueJWT(ctx context.Context, verifiedPasswordHash string) (string, error) {
	if s.m == nil || s.m.pg == nil {
		return "", errors.New("session store unavailable")
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		return "", err
	}
	claims, err := parseJWT(tok, s.jwtKey)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.m.pg.IssueAuthSession(ctx, tokenDigest(tok), tokenDigest(string(s.jwtKey)), verifiedPasswordHash, claims.ExpiresAt.Time); err != nil {
		return "", err
	}
	return tok, nil
}

func (s *Server) sessionActive(ctx context.Context, tok string) (bool, error) {
	if _, err := parseJWT(tok, s.jwtKey); err != nil {
		return false, nil
	}
	if s.m == nil || s.m.pg == nil {
		return false, errors.New("session store unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.m.pg.AuthSessionActive(ctx, tokenDigest(tok), tokenDigest(string(s.jwtKey)))
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) bool {
	active, err := s.sessionActive(r.Context(), extractToken(r))
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return false
	}
	if !active {
		writeErr(w, 401, "token is invalid, revoked or expired")
		return false
	}
	return true
}

// Authentication needs only a few short strings. Never allocate an unbounded
// anonymous JSON body before checking a setup token or password.
func decodeAuth(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(into)
	if err == nil {
		var extra any
		if tail := decoder.Decode(&extra); tail != io.EOF {
			if tail == nil {
				err = errors.New("multiple JSON values")
			} else {
				err = tail
			}
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, 413, "Authentication request is too large")
		} else {
			writeErr(w, 400, "Invalid request format")
		}
		return false
	}
	return true
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// Exempt only the exact public authentication routes, never a whole prefix.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if (r.Method == http.MethodGet && (p == "/api/auth/status" || p == "/api/health")) ||
			(r.Method == http.MethodPost && (p == "/api/auth/init" || p == "/api/auth/login")) {
			h.ServeHTTP(w, r)
			return
		}
		if !s.requireSession(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// A read failure must answer 503, not initialized:false: on initialized:false the
// frontend ships the user to /setup to set a password (login/page.tsx); wrapping a
// database outage in a 200 pushes the user toward overwriting the existing password.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// initSetupToken generates the one-time setup token when no admin password is set
// and writes it to the server log. Without it, anyone who can reach the port
// before the operator could claim the instance through POST /api/auth/init.
func (s *Server) initSetupToken() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if hash, _, err := s.m.pg.GetSetting(authPassKey); err == nil && hash != "" {
		return
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("[auth] generate setup token: %v", err)
	}
	s.setupToken = hex.EncodeToString(buf)
	log.Printf("[auth] no admin password is set. Setup token for the /setup page: %s", s.setupToken)
}

// checkSetupToken compares got with the active setup token in constant time.
// It fails when no token is active.
func (s *Server) checkSetupToken(got string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.setupToken)) == 1
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
// Requires the setup token from the server log.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "Password is already set")
		return
	}
	var req struct {
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if !decodeAuth(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeErr(w, 400, "Password cannot be empty")
		return
	}
	// 403, not 401: the frontend treats any 401 as an expired session and redirects to /login.
	if !s.checkSetupToken(req.SetupToken) {
		writeErr(w, 403, "Invalid setup token. The server log prints it at startup while no password is set")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// INSERT ... ON CONFLICT DO NOTHING instead of an upsert: the GetSetting above is
	// only a fast-fail path; the real "first-set-only" guarantee rests on the primary
	// key. bcrypt runs tens of milliseconds, another request may set the password meanwhile, and the read check itself can fail under an outage.
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !inserted {
		writeErr(w, 403, "Password is already set")
		return
	}
	s.setupMu.Lock()
	s.setupToken = ""
	s.setupMu.Unlock()
	tok, err := s.issueJWT(r.Context(), string(hash))
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// issued session AND the current password. The database atomically revokes every
// session (including the caller's) when the password row changes.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !s.requireSession(w, r) {
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !decodeAuth(w, r, &req) {
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "New password cannot be empty")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 403, "Current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	if err := pg.ChangeAuthPassword(r.Context(), hash, string(newHash)); err != nil {
		if errors.Is(err, db.ErrAuthCredentialsChanged) {
			writeErr(w, 409, "Credentials changed; sign in again")
			return
		}
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	s.login(w, r, pg.GetSetting, s.issueJWT)
}

// login is authLogin past the data-source check; getSetting is pg.GetSetting,
// a parameter so tests can run it without PostgreSQL. Every attempt counts
// against the caller's IP (s.loginLimit, keyed by clientIP) and a successful
// one clears it. There is no per-account lockout and no password length check here.
func (s *Server) login(w http.ResponseWriter, r *http.Request, getSetting func(string) (string, bool, error), issue func(context.Context, string) (string, error)) {
	ip := clientIP(r, s.trustedProxies)
	if wait := s.loginLimit.allow(ip); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, 429, fmt.Sprintf("Too many login attempts, try again in %d seconds", secs))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeAuth(w, r, &req) {
		return
	}
	if req.Username != "ARTEX" {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	hash, ok, err := getSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	tok, err := issue(r.Context(), hash)
	if err != nil {
		if errors.Is(err, db.ErrAuthCredentialsChanged) {
			writeErr(w, 401, "Credentials changed; sign in again")
			return
		}
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	s.loginLimit.reset(ip)
	writeJSON(w, 200, map[string]any{"token": tok})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.m.pg.RevokeAuthSession(ctx, tokenDigest(extractToken(r))); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

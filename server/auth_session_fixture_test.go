package server

import (
	"context"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// These existing HTTP tests previously fabricated stateless tokens. Test setup
// now explicitly activates its generated key and issues a persisted session.
// Production startup never activates a different key automatically.
func newTestServer(t *testing.T, ctx context.Context, m *Manager, skillDir, dataDir, _ string, opts ...Option) *Server {
	t.Helper()
	keyDir := t.TempDir()
	key, err := loadOrCreateJWTKey(keyDir, dataDir)
	if err != nil {
		panic(err)
	}
	if err := m.pg.ActivateAuthSigningKey(ctx, tokenDigest(string(key))); err != nil {
		panic(err)
	}
	return New(ctx, m, skillDir, dataDir, keyDir, opts...)
}

func issueTestSession(s *Server) (string, error) {
	if s.m == nil || s.m.pg == nil {
		return "", fmt.Errorf("test session requires a database")
	}
	if err := s.m.pg.ActivateAuthSigningKey(context.Background(), tokenDigest(string(s.jwtKey))); err != nil {
		return "", err
	}
	hash, ok, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		return "", err
	}
	if !ok || hash == "" {
		generated, err := bcrypt.GenerateFromPassword([]byte("synthetic-test-password"), bcrypt.MinCost)
		if err != nil {
			return "", err
		}
		if _, err := s.m.pg.InsertSettingIfAbsent(authPassKey, string(generated)); err != nil {
			return "", err
		}
		hash, _, err = s.m.pg.GetSetting(authPassKey)
		if err != nil {
			return "", err
		}
	}
	return s.issueJWT(context.Background(), hash)
}

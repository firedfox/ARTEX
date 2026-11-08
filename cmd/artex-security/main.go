// Command artex-security performs offline, explicitly applied key/session
// maintenance. It never accepts or prints a signing key or database password.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	return runWithInput(args, os.Stdin, out, errOut)
}

func runWithInput(args []string, input io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: artex-security <prepare-key|activate-key|revoke-sessions|reset-password> [--key-file PATH --data-dir PATH --skills-dir PATH] [--database NAME] [--password-stdin] [--apply]")
		return 2
	}
	command := args[0]
	if command != "prepare-key" && command != "activate-key" && command != "revoke-sessions" && command != "reset-password" {
		fmt.Fprintln(errOut, "unknown maintenance command")
		return 2
	}
	fs := flag.NewFlagSet("artex-security", flag.ContinueOnError)
	fs.SetOutput(errOut)
	keyFile := fs.String("key-file", "", "private key file (never pass key contents)")
	dataDir := fs.String("data-dir", "", "actual browsable workspace root")
	skillsDir := fs.String("skills-dir", "", "actual browsable skills root")
	database := fs.String("database", "", "expected pre-existing PostgreSQL database name")
	apply := fs.Bool("apply", false, "perform the named operation; omit to validate only")
	passwordStdin := fs.Bool("password-stdin", false, "read the new admin password as exact bytes from stdin (reset-password only)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(errOut, message); return 1 }
	var key []byte
	var password []byte
	if command == "reset-password" {
		if !*passwordStdin {
			return fail("reset-password requires --password-stdin; never pass passwords as arguments")
		}
		var err error
		password, err = io.ReadAll(io.LimitReader(input, 73))
		if err != nil || !utf8.Valid(password) || utf8.RuneCount(password) < 12 || len(password) > 72 {
			return fail("new password must be valid UTF-8, at least 12 characters and at most 72 bytes")
		}
	} else if *passwordStdin {
		return fail("password-stdin is only valid for reset-password")
	}
	if command == "prepare-key" || command == "activate-key" {
		if *keyFile == "" || *dataDir == "" || *skillsDir == "" {
			return fail("key-file, data-dir, and skills-dir are required; all parent/root directories must already exist")
		}
		if err := validateKeyPath(*keyFile, *dataDir, *skillsDir); err != nil {
			return fail(err.Error())
		}
		if command == "prepare-key" {
			if err := prepareKey(*keyFile, *apply); err != nil {
				return fail(err.Error())
			}
			if *apply {
				fmt.Fprintln(out, "Prepared a new private key file; the current server key and database were not changed.")
			} else {
				fmt.Fprintln(out, "Validated key destination. No changes; add --apply to create the new key file.")
			}
			return 0
		}
		var err error
		key, err = readKey(*keyFile)
		if err != nil {
			return fail(err.Error())
		}
	}
	if strings.TrimSpace(*database) == "" {
		return fail("database is required and must match the configured, pre-existing target database")
	}
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		return fail("PostgreSQL configuration is unavailable; use private ARTEX_CONFIG or ARTEX_PG_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := verifyDatabase(ctx, dsn, *database); err != nil {
		return fail(err.Error())
	}
	if !*apply {
		fmt.Fprintln(out, "Validated the target and dedicated runtime role. No changes; stop all ARTEX instances before applying maintenance.")
		return 0
	}
	store, err := db.Open(dsn)
	if err != nil {
		return fail("Could not open/migrate the confirmed application database; leave ARTEX stopped and inspect private database logs")
	}
	defer store.Close()
	switch command {
	case "activate-key":
		digest := sha256.Sum256(key)
		if err := store.RotateAuthSigningKey(ctx, hex.EncodeToString(digest[:])); err != nil {
			return fail("Key activation failed; leave all ARTEX instances stopped and retry with the intended key file")
		}
		fmt.Fprintf(out, "Activated key fingerprint SHA-256:%x; revoked every issued session.\n", digest)
	case "revoke-sessions":
		if err := store.RevokeAllAuthSessions(ctx); err != nil {
			return fail("Session revocation failed; leave ARTEX stopped and inspect private database logs")
		}
		fmt.Fprintln(out, "Revoked every issued session.")
	case "reset-password":
		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			return fail("Could not hash the new password")
		}
		if err := store.SetSetting("auth.password_hash", string(hash)); err != nil {
			return fail("Password reset failed; leave ARTEX stopped and inspect private database logs")
		}
		fmt.Fprintln(out, "Reset the administrator password and revoked every issued session.")
	}
	return 0
}

func verifyDatabase(ctx context.Context, dsn, expected string) error {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return errors.New("Could not open the configured database")
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	var actual string
	if err := conn.QueryRowContext(ctx, `SELECT current_database()`).Scan(&actual); err != nil {
		return errors.New("Could not verify the pre-existing target database")
	}
	if actual != expected {
		return errors.New("Configured database does not match --database; no changes applied")
	}
	return db.CheckRuntimeDSN(ctx, dsn)
}

func validateKeyPath(keyFile string, roots ...string) error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(keyFile))
	if err != nil {
		return errors.New("Key parent directory must already exist")
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return errors.New("Could not resolve key parent directory")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("Key parent must be a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("Key parent directory must have private permissions (0700)")
	}
	for _, root := range roots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return errors.New("Browsable roots must already exist and resolve successfully")
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return errors.New("Could not resolve browsable root")
		}
		rel, err := filepath.Rel(resolved, parent)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return errors.New("Key directory must be outside workspace and skills roots, including symlinks")
		}
	}
	return nil
}

func prepareKey(path string, apply bool) error {
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return errors.New("Key destination already exists or cannot be inspected; nothing was overwritten")
	}
	if !apply {
		return nil
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return errors.New("Could not obtain cryptographic randomness")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.New("Could not open the private key directory")
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("Could not exclusively create the new key file; nothing was overwritten")
	}
	defer file.Close()
	if _, err := io.WriteString(file, hex.EncodeToString(entropy[:])); err != nil {
		return errors.New("Key write failed; keep ARTEX stopped and inspect the incomplete file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("Key sync failed; keep ARTEX stopped and inspect the new file")
	}
	if err := file.Close(); err != nil {
		return errors.New("Key close failed; keep ARTEX stopped and inspect the new file")
	}
	if runtime.GOOS != "windows" {
		dir, err := root.Open(".")
		if err != nil {
			return errors.New("Could not sync the new key directory entry")
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil || closeErr != nil {
			return errors.New("Key directory sync failed; keep ARTEX stopped and inspect the new file")
		}
	}
	return nil
}

func readKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || info.Size() < 32 {
		return nil, errors.New("Key must be an existing bounded regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Key file permissions must be 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Could not read the key file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("Key file changed while being opened; leave ARTEX stopped")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(contents) > 4096 {
		return nil, errors.New("Could not read a bounded key file")
	}
	key := []byte(strings.TrimSpace(string(contents)))
	if len(key) < 32 {
		return nil, errors.New("Key is shorter than 32 bytes")
	}
	return key, nil
}

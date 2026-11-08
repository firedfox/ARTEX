package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Keep the offline migration's explicit object allowlist aligned with all three
// application schemas. This prevents a future table from silently retaining the
// legacy administrator as owner after a seemingly successful migration.
func TestAuthSessionRuntimeRoleMigrationManifest(t *testing.T) {
	b, err := os.ReadFile("../scripts/migrate-runtime-role.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	manifest := func(name string) []string {
		t.Helper()
		start := strings.Index(script, "INSERT INTO "+name+" VALUES")
		if start < 0 {
			t.Fatalf("missing %s allowlist", name)
		}
		block := strings.SplitN(script[start:], ";", 2)[0]
		var out []string
		for _, match := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(block, -1) {
			out = append(out, match[1])
		}
		slices.Sort(out)
		return out
	}
	var tables, functions []string
	for _, source := range []string{schemaSQL, llmRecordsSchema, llmUsageSchema} {
		for _, match := range regexp.MustCompile(`(?m)^CREATE TABLE IF NOT EXISTS ([a-z_]+)`).FindAllStringSubmatch(source, -1) {
			tables = append(tables, match[1])
		}
	}
	for _, match := range regexp.MustCompile(`(?m)^CREATE OR REPLACE FUNCTION ([a-z_]+)\(([^)]*)\)`).FindAllStringSubmatch(schemaSQL, -1) {
		args := ""
		if fields := strings.Fields(match[2]); len(fields) != 0 {
			args = fields[len(fields)-1]
		}
		functions = append(functions, match[1]+"("+args+")")
	}
	slices.Sort(tables)
	slices.Sort(functions)
	if got := manifest("artex_known_tables"); !slices.Equal(got, tables) {
		t.Fatalf("migration table allowlist differs from application schemas:\ngot %v\nwant %v", got, tables)
	}
	if got := manifest("artex_known_functions"); !slices.Equal(got, functions) {
		t.Fatalf("migration function allowlist differs from application schema:\ngot %v\nwant %v", got, functions)
	}
}

// This executes the actual Docker init hook and psql migration, then runs the
// actual Go Open/schema/seed path as their non-superuser. It creates and removes
// only uniquely named databases derived from an explicit loopback test DSN.
func TestAuthSessionRuntimeRoleMigrationPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("isolated PostgreSQL required; CI rejects skipped security tests")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") ||
		(u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") ||
		!strings.Contains(strings.ToLower(u.Path), "test") || u.User == nil || u.User.Username() == "" {
		t.Fatal("role migration tests require an explicit loopback test database and maintenance user")
	}
	psql, err := exec.LookPath("psql")
	if err != nil {
		t.Fatal("configured PostgreSQL tests require the psql client")
	}
	adminName := u.User.Username()
	adminPassword, _ := u.User.Password()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(entropy[:]) // Disposable test credential; never logged.
	base := strings.TrimPrefix(u.Path, "/")
	if len(base) > 25 {
		base = base[:25]
	}
	prefix := base + "_roles_" + hex.EncodeToString(entropy[:6])
	fresh, legacy, unrelated := prefix+"_fresh", prefix+"_old", prefix+"_other"
	redact := func(value string) string {
		for _, secret := range []string{password, adminPassword, dsn} {
			if secret != "" {
				value = strings.ReplaceAll(value, secret, "[redacted]")
			}
		}
		return value
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("could not configure the isolated PostgreSQL administrator")
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(t.Context()); err != nil {
		t.Fatal("configured isolated PostgreSQL administrator is unavailable")
	}
	var roleExists bool
	if err := admin.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='artex_app')`).Scan(&roleExists); err != nil || roleExists {
		t.Fatal("role migration fixture requires artex_app to be absent; it never changes an existing role")
	}
	var created []string
	createdRole := false
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, name := range created {
			if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
				t.Errorf("could not remove isolated migration database %s", name)
			}
		}
		if createdRole {
			if _, err := admin.ExecContext(ctx, `DROP ROLE IF EXISTS artex_app`); err != nil {
				t.Error("could not remove isolated migration role")
			}
		}
	})
	for _, name := range []string{fresh, legacy, unrelated} {
		if _, err := admin.ExecContext(t.Context(), `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatal("test administrator could not create an isolated migration database")
		}
		created = append(created, name)
	}
	withDatabase := func(name, role, pass string) string {
		value := *u
		value.Path = "/" + name
		if role != "" {
			value.User = url.UserPassword(role, pass)
		}
		return value.String()
	}
	openAdmin := func(name string) *sql.DB {
		t.Helper()
		conn, err := sql.Open("pgx", withDatabase(name, "", ""))
		if err != nil {
			t.Fatal("could not open the isolated migration database")
		}
		return conn
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	sslmode := u.Query().Get("sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}
	var baseEnv []string
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		if strings.HasPrefix(key, "PG") || key == "ARTEX_APP_PASSWORD" || key == "POSTGRES_USER" || key == "POSTGRES_DB" {
			continue
		}
		baseEnv = append(baseEnv, item)
	}
	baseEnv = append(baseEnv, "PGHOST="+u.Hostname(), "PGPORT="+port, "PGUSER="+adminName,
		"PGPASSWORD="+adminPassword, "PGSSLMODE="+sslmode, "PGCONNECT_TIMEOUT=5")
	run := func(name string, bootstrap bool, expected, apply string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		var cmd *exec.Cmd
		if bootstrap {
			path, _ := filepath.Abs("../scripts/bootstrap-postgres.sh")
			cmd = exec.CommandContext(ctx, "bash", path)
		} else {
			path, _ := filepath.Abs("../scripts/migrate-runtime-role.sql")
			cmd = exec.CommandContext(ctx, psql, "--no-psqlrc", "--no-password", "--dbname", name,
				"--set", "expected_database="+expected, "--set", "previous_owner="+adminName,
				"--set", "apply_migration="+apply, "--file", path)
		}
		cmd.Env = append(slices.Clone(baseEnv), "POSTGRES_USER="+adminName, "POSTGRES_DB="+name, "ARTEX_APP_PASSWORD="+password)
		output, err := cmd.CombinedOutput()
		if strings.Contains(string(output), password) {
			t.Fatal("provisioning script disclosed the disposable plaintext credential")
		}
		return redact(string(output)), err
	}
	assertOwner := func(name, table, want string) {
		t.Helper()
		conn := openAdmin(name)
		defer conn.Close()
		var got string
		if err := conn.QueryRowContext(t.Context(), `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=to_regclass($1)`, "public."+table).Scan(&got); err != nil || got != want {
			t.Fatalf("isolated %s.%s owner=%q want=%q (read error=%v)", name, table, got, want, err != nil)
		}
	}
	checkApplication := func(name string) {
		t.Helper()
		appDSN := withDatabase(name, "artex_app", password)
		if err := CheckRuntimeDSN(t.Context(), appDSN); err != nil {
			t.Fatalf("provisioned role failed runtime privilege validation: %v", err)
		}
		app, err := Open(appDSN)
		if err != nil {
			t.Fatalf("provisioned role could not run real Open/schema/seed: %s", redact(err.Error()))
		}
		defer app.Close()
		if err := app.EnsureLLMRecordsTable(); err != nil {
			t.Fatalf("provisioned role could not migrate LLM records: %s", redact(err.Error()))
		}
		if err := app.EnsureLLMUsageTable(); err != nil {
			t.Fatalf("provisioned role could not migrate LLM usage: %s", redact(err.Error()))
		}
		var seeded int
		if err := app.QueryRowContext(t.Context(), `SELECT count(*) FROM agents WHERE builtin`).Scan(&seeded); err != nil || seeded == 0 {
			t.Fatal("runtime role failed to seed builtin agents")
		}
	}
	if output, err := run(fresh, true, "", ""); err != nil {
		t.Fatalf("fresh bootstrap failed: %v\n%s", err, output)
	}
	createdRole = true
	checkApplication(fresh)
	assertOwner(fresh, "settings", "artex_app")
	if output, err := run(fresh, true, "", ""); err == nil || !strings.Contains(output, "already exists") {
		t.Fatalf("bootstrap did not reject an existing role: %v\n%s", err, output)
	}
	checkApplication(fresh) // A rejected re-run must not change the login password.

	old := openAdmin(legacy)
	for _, source := range []string{schemaSQL, llmRecordsSchema, llmRecordsMigrate, llmUsageSchema, `CREATE EXTENSION pgcrypto WITH SCHEMA public`} {
		if _, err := old.ExecContext(t.Context(), source); err != nil {
			old.Close()
			t.Fatalf("could not prepare the isolated legacy schema: %s", redact(err.Error()))
		}
	}
	old.Close()
	if output, err := run(legacy, false, legacy, "no"); err != nil || !strings.Contains(output, "Preview only") {
		t.Fatalf("migration preview failed: %v\n%s", err, output)
	}
	assertOwner(legacy, "settings", adminName)
	if output, err := run(legacy, false, unrelated, "yes"); err == nil || !strings.Contains(output, "expected_database") {
		t.Fatalf("migration did not reject the wrong explicit target: %v\n%s", err, output)
	}
	assertOwner(legacy, "settings", adminName)

	old = openAdmin(legacy)
	if _, err := old.ExecContext(t.Context(), `CREATE TABLE public.unrelated_application (id integer)`); err != nil {
		old.Close()
		t.Fatal(err)
	}
	old.Close()
	if output, err := run(legacy, false, legacy, "yes"); err == nil || !strings.Contains(output, "unknown public object") {
		t.Fatalf("migration did not reject an unrelated table: %v\n%s", err, output)
	}
	assertOwner(legacy, "settings", adminName)
	old = openAdmin(legacy)
	if _, err := old.ExecContext(t.Context(), `DROP TABLE public.unrelated_application`); err != nil {
		old.Close()
		t.Fatal(err)
	}
	if output, err := run(legacy, false, legacy, "yes"); err == nil || !strings.Contains(output, "close other connections") {
		old.Close()
		t.Fatalf("migration did not reject an active legacy connection: %v\n%s", err, output)
	}
	old.Close()
	if output, err := run(legacy, false, legacy, "yes"); err != nil {
		t.Fatalf("legacy migration failed: %v\n%s", err, output)
	}
	for _, table := range []string{"settings", "llm_records", "llm_usage", "assets_id_seq"} {
		assertOwner(legacy, table, "artex_app")
	}
	checkApplication(legacy)
	// Re-running a completed migration is safe, but still requires the same
	// explicit target, old owner, no other connections, and object validation.
	if output, err := run(legacy, false, legacy, "yes"); err != nil {
		t.Fatalf("migration could not safely resume: %v\n%s", err, output)
	}
	var privileged bool
	if err := admin.QueryRowContext(t.Context(), `SELECT rolsuper FROM pg_roles WHERE rolname=$1`, adminName).Scan(&privileged); err != nil || !privileged {
		t.Fatal("migration changed maintenance administrator privileges")
	}
	for _, name := range []string{fresh, legacy, unrelated} {
		var owner string
		if err := admin.QueryRowContext(t.Context(), `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1`, name).Scan(&owner); err != nil || owner != adminName {
			t.Fatalf("database %s ownership changed", name)
		}
	}
	old = openAdmin(legacy)
	defer old.Close()
	var extensionOwner string
	if err := old.QueryRowContext(t.Context(), `SELECT pg_get_userbyid(extowner) FROM pg_extension WHERE extname='pgcrypto'`).Scan(&extensionOwner); err != nil || extensionOwner != adminName {
		t.Fatal("migration reassigned extension ownership")
	}
	var functionOwner string
	if err := old.QueryRowContext(t.Context(), `SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid='public.crypt(text,text)'::regprocedure`).Scan(&functionOwner); err != nil || functionOwner != adminName {
		t.Fatal("migration reassigned extension member ownership")
	}
}

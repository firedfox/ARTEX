package db

import (
	"context"
	"database/sql"
	"errors"
)

var ErrUnsafeRuntimeRole = errors.New("PostgreSQL runtime role has server administration or host-file privileges; configure a dedicated application role")

// CheckRuntimeDSN runs before migrations or task startup. Both session_user and
// any role reachable through membership are checked: NOINHERIT alone does not
// prevent SET ROLE. The current in-process migrations require ownership of the
// application's tables/functions/sequences plus schema CREATE/USAGE; neither
// database ownership nor PostgreSQL server administration is required.
func CheckRuntimeDSN(ctx context.Context, dsn string) error {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return errors.New("PostgreSQL runtime role check could not open the connection")
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	return checkRuntimePrivileges(ctx, conn)
}

type roleQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func checkRuntimePrivileges(ctx context.Context, q roleQueryer) error {
	var unsafe bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM pg_roles r
  WHERE (r.rolname = session_user OR r.rolname = current_user
    OR pg_has_role(session_user, r.oid, 'MEMBER')
    OR pg_has_role(current_user, r.oid, 'MEMBER'))
  AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
    OR r.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program'))
)`).Scan(&unsafe)
	if err != nil {
		// Driver errors may include connection strings or SQL context. Do not echo
		// them from startup or maintenance operations that use real credentials.
		return errors.New("PostgreSQL runtime role check failed")
	}
	if unsafe {
		return ErrUnsafeRuntimeRole
	}
	return nil
}

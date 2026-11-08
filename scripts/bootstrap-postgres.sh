#!/usr/bin/env bash
# Official postgres image init hook, for an empty ARTEX database only.
# POSTGRES_USER remains the maintenance administrator. Never run this with -x.
# ARTEX_APP_PASSWORD is read from the environment, never argv or a SQL literal.
set +x
set -euo pipefail

: "${POSTGRES_USER:?POSTGRES_USER must name the maintenance administrator}"
: "${POSTGRES_DB:?POSTGRES_DB must name the dedicated ARTEX database}"
: "${ARTEX_APP_PASSWORD:?ARTEX_APP_PASSWORD must be set for initial provisioning}"

if [[ "$POSTGRES_USER" == artex_app ]]; then
  printf '%s\n' 'POSTGRES_USER must be separate from the fixed runtime role artex_app.' >&2
  exit 1
fi
if [[ ${#ARTEX_APP_PASSWORD} -lt 32 || "$ARTEX_APP_PASSWORD" == *$'\n'* || "$ARTEX_APP_PASSWORD" == *$'\r'* ]]; then
  printf '%s\n' 'ARTEX_APP_PASSWORD must contain at least 32 characters and no line breaks.' >&2
  exit 1
fi
# psql \password reads /dev/tty when one is present. An init hook must be
# noninteractive so its two password reads come only from the private pipe.
if [[ -t 0 || -t 1 || -t 2 ]] || ( : </dev/tty ) 2>/dev/null; then
  printf '%s\n' 'Run this hook noninteractively during postgres initialization, without a controlling terminal.' >&2
  exit 1
fi

artex_psql=(psql --no-psqlrc --no-password --quiet --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1)
"${artex_psql[@]}" <<'SQL'
BEGIN;
SET LOCAL search_path = pg_catalog;
DO $$
BEGIN
    IF current_user <> session_user OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user) THEN
        RAISE EXCEPTION 'bootstrap requires the separate maintenance administrator';
    END IF;
    IF current_database() IN ('postgres', 'template0', 'template1') THEN
        RAISE EXCEPTION 'bootstrap requires a dedicated ARTEX database';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'artex_app') THEN
        RAISE EXCEPTION 'artex_app already exists; bootstrap will not reset or demote an existing role';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace)
       OR EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = 'public'::regnamespace) THEN
        RAISE EXCEPTION 'database is not empty; use the reviewed runtime role migration procedure';
    END IF;
END;
$$;
CREATE ROLE artex_app NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
COMMIT;
SQL

# libpq creates a SCRAM verifier client-side; the plaintext password is never
# embedded in a server query, psql command line, or echoed script. Failure leaves
# the role NOLOGIN for an operator to inspect, rather than partly provisioning it.
printf '%s\n%s\n' "$ARTEX_APP_PASSWORD" "$ARTEX_APP_PASSWORD" |
  PGOPTIONS="${PGOPTIONS:-} -c password_encryption=scram-sha-256 -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse" \
    "${artex_psql[@]}" --set VERBOSITY=terse --set SHOW_CONTEXT=never --command '\password artex_app'
unset ARTEX_APP_PASSWORD

"${artex_psql[@]}" <<'SQL'
BEGIN;
SELECT format('GRANT CONNECT ON DATABASE %I TO artex_app', current_database()) \gexec
GRANT USAGE, CREATE ON SCHEMA public TO artex_app;
SELECT format('ALTER ROLE artex_app IN DATABASE %I SET search_path = public', current_database()) \gexec
ALTER ROLE artex_app LOGIN;
COMMIT;
SQL
printf '%s\n' 'Provisioned artex_app. The maintenance role and database ownership are unchanged.'

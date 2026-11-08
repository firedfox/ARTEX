-- Offline migration of a dedicated ARTEX database. Run with psql -X and a
-- maintenance login, after stopping every ARTEX instance and taking a backup.
-- Required: -v expected_database=NAME -v previous_owner=OLD_ROLE
-- Preview is the default. Add -v apply_migration=yes to commit the same checks.
-- The fixed artex_app role must already have its own password (use \password).
-- This does not change passwords, role attributes, database/schema ownership,
-- other databases, tablespaces, or extension-owned objects. No REASSIGN OWNED.
\set ON_ERROR_STOP on
\set QUIET on
\if :{?expected_database}
\else
\set expected_database ''
\endif
\if :{?previous_owner}
\else
\set previous_owner ''
\endif
\if :{?apply_migration}
\else
\set apply_migration no
\endif

BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
CREATE TEMP TABLE artex_migration_input(expected_database text, previous_owner text) ON COMMIT DROP;
INSERT INTO artex_migration_input VALUES (:'expected_database', :'previous_owner');
CREATE TEMP TABLE artex_known_tables(name text PRIMARY KEY) ON COMMIT DROP;
-- Maintained with db/schema.sql plus the two lazy schemas in db/commands.go
-- and db/llm_usage.go. Absent newer tables are created later by db.Open.
INSERT INTO artex_known_tables VALUES
('companies'), ('assets'), ('company_scope'), ('explorations'),
('exploration_nodes'), ('exploration_edges'), ('exploration_anchors'),
('task_constraints'), ('activity'), ('main_sessions'), ('settings'),
('auth_state'), ('auth_sessions'), ('llm_profiles'), ('llm_profile_health'),
('task_categories'), ('tasks'), ('task_archives'), ('task_templates'),
('task_relations'), ('task_asset_links'), ('task_llm_profiles'), ('task_scope'),
('agents'), ('agent_prompts'), ('agent_prompt_vars'), ('mcp_servers'),
('mcp_tools_cache'), ('agent_visibility'), ('agent_skill_visibility'),
('skill_usage'), ('tool_usage'), ('tools'), ('conversations'),
('conversation_activities'), ('agent_triggers'), ('scheduler_state'),
('intercept_rules'), ('intercept_pending'), ('findings'), ('finding_retests'),
('traffic_evidence_snapshots'), ('finding_traffic_bindings'), ('server_logs'),
('side_question_sessions'), ('side_question_requests'),
('asset_intercept_rules'), ('task_intercept_rules'), ('task_credentials'),
('notification_channels'), ('notification_events'), ('notification_deliveries'),
('rsi_lessons'), ('rsi_lesson_evidence'), ('rsi_lesson_usage'),
('llm_records'), ('llm_usage');
CREATE TEMP TABLE artex_known_functions(signature text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO artex_known_functions VALUES
('set_updated_at()'), ('try_inet(text)'), ('revoke_sessions_on_password_change()'),
('sync_task_asset_links()'), ('stop_deleted_conversation_retest()');

DO $$
DECLARE
    input record;
    app record;
    old_oid oid;
    item record;
    anchor text;
BEGIN
    SELECT * INTO input FROM pg_temp.artex_migration_input;
    IF input.expected_database = '' OR current_database() <> input.expected_database
       OR current_database() IN ('postgres', 'template0', 'template1') THEN
        RAISE EXCEPTION 'expected_database must explicitly match the dedicated ARTEX database';
    END IF;
    IF current_user <> session_user OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user) THEN
        RAISE EXCEPTION 'migration requires the separate maintenance administrator';
    END IF;
    SELECT oid INTO old_oid FROM pg_roles WHERE rolname = input.previous_owner;
    IF old_oid IS NULL OR input.previous_owner = 'artex_app' THEN
        RAISE EXCEPTION 'previous_owner must name the existing, separate legacy owner';
    END IF;
    SELECT * INTO app FROM pg_roles WHERE rolname = 'artex_app';
    IF NOT FOUND OR NOT app.rolcanlogin OR app.rolsuper OR app.rolcreatedb OR app.rolcreaterole
       OR app.rolreplication OR app.rolbypassrls THEN
        RAISE EXCEPTION 'create artex_app as a separate nonprivileged LOGIN role with its own password first';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = app.oid) THEN
        RAISE EXCEPTION 'artex_app must not inherit or assume any other role';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_authid WHERE oid = app.oid AND rolpassword LIKE 'SCRAM-SHA-256$%') THEN
        RAISE EXCEPTION 'set a separate SCRAM password for artex_app with the psql password command first';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_database WHERE datdba = app.oid AND datname <> current_database())
       OR EXISTS (SELECT 1 FROM pg_tablespace WHERE spcowner = app.oid) THEN
        RAISE EXCEPTION 'artex_app must not own other databases or tablespaces';
    END IF;
    -- Match the application schema lock. All instances must remain stopped until
    -- the new DSN is installed; a concurrent old process must not recreate objects.
    PERFORM pg_advisory_xact_lock(7337741001);
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
               AND pid <> pg_backend_pid() AND backend_type = 'client backend') THEN
        RAISE EXCEPTION 'stop every ARTEX instance and close other connections to this database before migrating';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public', 'information_schema')
               AND nspname !~ '^pg_') THEN
        RAISE EXCEPTION 'database contains another application schema; review it manually instead of bulk migration';
    END IF;
    FOREACH anchor IN ARRAY ARRAY['settings', 'assets', 'tasks', 'agents'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace
                       AND relname = anchor AND relkind = 'r') THEN
            RAISE EXCEPTION 'required ARTEX anchor table public.% is missing', anchor;
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1 FROM pg_depend dep JOIN pg_class seq ON seq.oid = dep.objid AND seq.relkind = 'S'
        JOIN pg_class tbl ON tbl.oid = dep.refobjid
        JOIN pg_attribute col ON col.attrelid = tbl.oid AND col.attnum = dep.refobjsubid
        JOIN pg_temp.artex_known_tables known ON known.name = tbl.relname
        WHERE dep.classid = 'pg_class'::regclass AND dep.refclassid = 'pg_class'::regclass
          AND dep.deptype IN ('a', 'i') AND tbl.relnamespace = 'public'::regnamespace
          AND (seq.relnamespace <> 'public'::regnamespace OR col.attname NOT IN ('id', 'ordinal')
               OR seq.relowner NOT IN (old_oid, app.oid)
               OR EXISTS (SELECT 1 FROM pg_depend ext WHERE ext.classid = 'pg_class'::regclass
                          AND ext.objid = seq.oid AND ext.deptype = 'e'))
    ) THEN
        RAISE EXCEPTION 'ARTEX table has an unexpected owned sequence; review before transferring its dependency set';
    END IF;

    FOR item IN SELECT c.oid, c.relname, c.relkind, c.relowner
                FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace LOOP
        IF EXISTS (SELECT 1 FROM pg_depend WHERE classid = 'pg_class'::regclass
                   AND objid = item.oid AND deptype = 'e') THEN
            IF EXISTS (SELECT 1 FROM pg_temp.artex_known_tables WHERE name = item.relname) THEN
                RAISE EXCEPTION 'ARTEX table name public.% belongs to an extension; refusing ownership transfer', item.relname;
            END IF;
            CONTINUE;
        END IF;
        IF item.relkind = 'r' AND EXISTS (SELECT 1 FROM pg_temp.artex_known_tables WHERE name = item.relname) THEN
            IF item.relowner NOT IN (old_oid, app.oid) THEN
                RAISE EXCEPTION 'public.% has an unexpected owner', item.relname;
            END IF;
        ELSIF item.relkind = 'S' AND EXISTS (
            SELECT 1 FROM pg_depend dep JOIN pg_class tbl ON tbl.oid = dep.refobjid
            JOIN pg_attribute col ON col.attrelid = tbl.oid AND col.attnum = dep.refobjsubid
            JOIN pg_temp.artex_known_tables known ON known.name = tbl.relname
            WHERE dep.classid = 'pg_class'::regclass AND dep.objid = item.oid
              AND dep.refclassid = 'pg_class'::regclass AND dep.deptype IN ('a', 'i')
              AND tbl.relnamespace = 'public'::regnamespace AND tbl.relkind = 'r'
              AND col.attname IN ('id', 'ordinal')
        ) THEN
            IF item.relowner NOT IN (old_oid, app.oid) THEN
                RAISE EXCEPTION 'owned sequence public.% has an unexpected owner', item.relname;
            END IF;
        ELSIF item.relkind = 'i' AND EXISTS (
            SELECT 1 FROM pg_index idx JOIN pg_class tbl ON tbl.oid = idx.indrelid
            JOIN pg_temp.artex_known_tables known ON known.name = tbl.relname
            WHERE idx.indexrelid = item.oid AND tbl.relnamespace = 'public'::regnamespace AND tbl.relkind = 'r'
        ) THEN
            NULL; -- ALTER TABLE OWNER transfers its indexes as one dependency set.
        ELSE
            RAISE EXCEPTION 'unknown public object % (kind %); review manually before migration', item.relname, item.relkind;
        END IF;
    END LOOP;
    FOR item IN SELECT p.oid, p.proowner, p.prokind,
                       p.proname || '(' || oidvectortypes(p.proargtypes) || ')' AS signature
                FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace LOOP
        IF EXISTS (SELECT 1 FROM pg_depend WHERE classid = 'pg_proc'::regclass
                   AND objid = item.oid AND deptype = 'e') THEN
            IF EXISTS (SELECT 1 FROM pg_temp.artex_known_functions WHERE signature = item.signature) THEN
                RAISE EXCEPTION 'ARTEX function % belongs to an extension; refusing ownership transfer', item.signature;
            END IF;
            CONTINUE;
        END IF;
        IF item.prokind <> 'f' OR NOT EXISTS (SELECT 1 FROM pg_temp.artex_known_functions WHERE signature = item.signature)
           OR item.proowner NOT IN (old_oid, app.oid) THEN
            RAISE EXCEPTION 'unknown function or owner for public.%; review manually before migration', item.signature;
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_type typ WHERE typ.typnamespace = 'public'::regnamespace
               AND typ.typrelid = 0 AND typ.typcategory <> 'A'
               AND NOT EXISTS (SELECT 1 FROM pg_depend WHERE classid = 'pg_type'::regclass
                               AND objid = typ.oid AND deptype = 'e')) THEN
        RAISE EXCEPTION 'public contains a standalone type; review manually before migration';
    END IF;
END;
$$;

SELECT current_database() AS verified_database, :'previous_owner' AS previous_owner,
       'artex_app' AS runtime_role,
       (SELECT count(*) FROM pg_class c JOIN pg_temp.artex_known_tables k ON k.name = c.relname
        WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r') AS tables_to_own;
SELECT 'table' AS object_kind, 'public.' || quote_ident(c.relname) AS object_name,
       pg_get_userbyid(c.relowner) AS current_owner
FROM pg_class c JOIN pg_temp.artex_known_tables k ON k.name = c.relname
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
UNION ALL
SELECT 'function', 'public.' || k.signature, pg_get_userbyid(p.proowner)
FROM pg_proc p JOIN pg_temp.artex_known_functions k
ON k.signature = p.proname || '(' || oidvectortypes(p.proargtypes) || ')'
WHERE p.pronamespace = 'public'::regnamespace
ORDER BY object_kind, object_name;
SELECT :'apply_migration' = 'yes' AS artex_apply \gset
\if :artex_apply
DO $$
DECLARE item record;
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO artex_app', current_database());
    GRANT USAGE, CREATE ON SCHEMA public TO artex_app;
    EXECUTE format('ALTER ROLE artex_app IN DATABASE %I SET search_path = public', current_database());
    FOR item IN SELECT c.relname FROM pg_class c
                JOIN pg_temp.artex_known_tables k ON k.name = c.relname
                WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' ORDER BY c.relname LOOP
        EXECUTE format('ALTER TABLE public.%I OWNER TO artex_app', item.relname);
    END LOOP;
    FOR item IN SELECT p.proname, oidvectortypes(p.proargtypes) AS args FROM pg_proc p
                JOIN pg_temp.artex_known_functions k
                ON k.signature = p.proname || '(' || oidvectortypes(p.proargtypes) || ')'
                WHERE p.pronamespace = 'public'::regnamespace LOOP
        EXECUTE format('ALTER FUNCTION public.%I(%s) OWNER TO artex_app', item.proname, item.args);
    END LOOP;
END;
$$;
COMMIT;
\echo 'ARTEX object ownership migrated. Maintenance role, database, tablespaces, and extensions were not reassigned.'
\else
ROLLBACK;
\echo 'Preview only: no changes committed. Re-run with apply_migration=yes after reviewing the verified target and object list.'
\endif

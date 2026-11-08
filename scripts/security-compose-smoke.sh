#!/usr/bin/env bash
# Exercise the actual image, Compose restrictions, first-start database hook,
# and offline key rotation. Only a disposable GitHub-hosted runner may run this.
set +x
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted || ${RUNNER_OS:-} != Linux ]]; then
  printf '%s\n' 'This smoke test requires a disposable GitHub-hosted Linux runner.' >&2
  exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"

artex_repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
artex_temp=$(mktemp -d "$RUNNER_TEMP/artex-security-XXXXXX")
artex_project="artex-security-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
artex_compose=(docker compose --project-name "$artex_project" --project-directory "$artex_repo"
  --env-file "$artex_temp/ci.env" -f "$artex_repo/docker-compose.yml" -f "$artex_temp/override.yml")
artex_started=false
cleanup() {
  local status=$?
  trap - EXIT
  if [[ $artex_started == true ]]; then
    if [[ $status -ne 0 ]]; then
      "${artex_compose[@]}" ps --all || true
      # Never dump the configuration, environment, or first-setup credentials.
      "${artex_compose[@]}" logs --no-color --tail=80 artex 2>&1 |
        sed -E '/[Tt]oken|[Pp]assword|[Ss]ecret|[Kk]ey|postgres:|postgresql:/d' || true
    fi
    "${artex_compose[@]}" down --volumes --remove-orphans || status=1
  fi
  # The only removed path is the private mktemp directory created above.
  sudo rm -rf --one-file-system -- "$artex_temp"
  exit "$status"
}
trap cleanup EXIT

umask 077
mkdir "$artex_temp/data" "$artex_temp/keys" "$artex_temp/skills"
cp -R "$artex_repo/skills/." "$artex_temp/skills/"
python3 - "$artex_temp" <<'PY'
import json
import secrets
import sys
from pathlib import Path

root = Path(sys.argv[1])
admin = secrets.token_hex(32)
app = secrets.token_hex(32)
(root / "ci.env").write_text("\n".join([
    "POSTGRES_USER=artex_ci_owner",
    "POSTGRES_DB=artex_security_ci",
    "POSTGRES_PASSWORD=" + admin,
    "ARTEX_APP_PASSWORD=" + app,
    "ARTEX_PG_DSN=postgres://artex_app:" + app + "@postgres:5432/artex_security_ci?sslmode=disable",
    "ARTEX_BIND_ADDR=127.0.0.1",
    "ARTEX_VERSION=security-ci",
]) + "\n")
# JSON is a valid Compose input. Volume merging replaces each matching target.
(root / "override.yml").write_text(json.dumps({"services": {"artex": {
    "image": "artex:security-ci",
    "volumes": [
        {"type": "bind", "source": str(root / name), "target": "/app/" + name}
        for name in ("data", "keys", "skills")
    ],
}}}))
PY
sudo chown -R 10001:10001 "$artex_temp/data" "$artex_temp/keys" "$artex_temp/skills"
sudo chmod 0700 "$artex_temp/data" "$artex_temp/keys" "$artex_temp/skills"
"${artex_compose[@]}" config --quiet
artex_started=true
"${artex_compose[@]}" up --detach --no-build

wait_for_health() {
  local attempt code
  for ((attempt = 0; attempt < 90; attempt++)); do
    code=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 http://127.0.0.1:8787/api/health || true)
    if [[ $code == 200 ]]; then
      return 0
    fi
    sleep 1
  done
  printf '%s\n' 'The container did not become healthy within the bounded startup window.' >&2
  return 1
}
wait_for_health
artex_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 http://127.0.0.1:8787/api/workspace/list)
[[ $artex_code == 401 ]] || { printf '%s\n' 'Anonymous workspace access was not rejected.' >&2; exit 1; }

artex_container=$("${artex_compose[@]}" ps --quiet artex)
docker inspect "$artex_container" | python3 -c '
import json, sys
config = json.load(sys.stdin)[0]
host = config["HostConfig"]
assert config["Config"]["User"] == "10001:10001", "wrong runtime user"
assert host["ReadonlyRootfs"], "root filesystem is writable"
assert "ALL" in host["CapDrop"], "capabilities were not dropped"
assert any(x in {"no-new-privileges", "no-new-privileges:true"} for x in host["SecurityOpt"]), "privilege escalation is enabled"
names = {item.split("=", 1)[0] for item in config["Config"]["Env"]}
assert not names.intersection({"POSTGRES_PASSWORD", "ARTEX_APP_PASSWORD"}), "maintenance credentials entered the app container"
print("Verified UID, read-only root, dropped capabilities, no-new-privileges, and separated database credentials.")
'
[[ $("${artex_compose[@]}" exec -T artex id -u) == 10001 ]]
if "${artex_compose[@]}" exec -T artex sh -c 'touch /app/security-smoke-write' 2>/dev/null; then
  printf '%s\n' 'The runtime unexpectedly wrote to its root filesystem.' >&2
  exit 1
fi
[[ $(sudo stat -c '%a:%u:%g' "$artex_temp/keys/jwt.key") == 600:10001:10001 ]]

artex_psql=("${artex_compose[@]}" exec -T postgres psql -X --no-password --quiet --tuples-only --no-align
  --username artex_ci_owner --dbname artex_security_ci --set ON_ERROR_STOP=1)
[[ $("${artex_psql[@]}" --command "SELECT rolcanlogin AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname='artex_app'") == t ]]
[[ $("${artex_psql[@]}" --command "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.settings'::regclass") == artex_app ]]
artex_generation=$("${artex_psql[@]}" --command 'SELECT generation FROM auth_state WHERE singleton')
[[ -n $artex_generation ]]
"${artex_psql[@]}" --command "INSERT INTO auth_sessions(token_hash,generation,expires_at) SELECT repeat('a',64),generation,now()+interval '1 hour' FROM auth_state WHERE singleton"

# No server instance may run while the key file and database are changed.
"${artex_compose[@]}" stop artex
artex_maintenance=("${artex_compose[@]}" run -T --rm --no-deps --entrypoint /app/artex-security artex)
"${artex_maintenance[@]}" prepare-key --key-file /app/keys/jwt.next --data-dir /app/data --skills-dir /app/skills
if sudo test -e "$artex_temp/keys/jwt.next"; then
  printf '%s\n' 'The default dry run unexpectedly created a key.' >&2
  exit 1
fi
"${artex_maintenance[@]}" prepare-key --key-file /app/keys/jwt.next --data-dir /app/data --skills-dir /app/skills --apply
sudo mv -T -- "$artex_temp/keys/jwt.next" "$artex_temp/keys/jwt.key"
sudo python3 - "$artex_temp/keys" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
"${artex_maintenance[@]}" activate-key --key-file /app/keys/jwt.key --data-dir /app/data --skills-dir /app/skills --database artex_security_ci
[[ $("${artex_psql[@]}" --command 'SELECT generation FROM auth_state WHERE singleton') == "$artex_generation" ]]
"${artex_maintenance[@]}" activate-key --key-file /app/keys/jwt.key --data-dir /app/data --skills-dir /app/skills --database artex_security_ci --apply
[[ $("${artex_psql[@]}" --command 'SELECT count(*) FROM auth_sessions') == 0 ]]
[[ $("${artex_psql[@]}" --command 'SELECT generation FROM auth_state WHERE singleton') != "$artex_generation" ]]
[[ $(sudo stat -c '%a:%u:%g' "$artex_temp/keys/jwt.key") == 600:10001:10001 ]]
"${artex_compose[@]}" start artex
wait_for_health
printf '%s\n' 'Compose startup, least-privilege runtime, offline key rotation, session revocation, and restart passed.'

#!/usr/bin/env bash
# Reset the administrator password through the reviewed maintenance binary.
# Secrets are read silently and sent only on stdin; never use bash -x.
set +x
set -euo pipefail

artex_reset_mode=local
artex_reset_database=
artex_reset_config=
artex_reset_root="$(cd "$(dirname "$0")" && pwd)"
artex_reset_binary="$artex_reset_root/artex-security"

usage() {
  printf '%s\n' 'Usage: reset-password.sh --database NAME [--mode local|docker] [--config PRIVATE_CONFIG_PATH]'
  printf '%s\n' 'All ARTEX instances must be stopped. Use a dedicated runtime-role DSN in ARTEX_CONFIG/ARTEX_PG_DSN.'
  printf '%s\n' 'The new password is entered silently; all issued sessions are revoked.'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database|-d) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; artex_reset_database="$2"; shift 2 ;;
    --mode|-m) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; artex_reset_mode="$2"; shift 2 ;;
    --config) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; artex_reset_config="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf '%s\n' 'Unsupported argument. Password and DSN command-line arguments are intentionally not accepted.' >&2; exit 2 ;;
  esac
done
[[ -n "$artex_reset_database" ]] || { usage >&2; exit 2; }
[[ "$artex_reset_mode" == local || "$artex_reset_mode" == docker ]] || { usage >&2; exit 2; }
if [[ "$artex_reset_mode" == local ]]; then
  [[ -x "$artex_reset_binary" ]] || { printf '%s\n' 'Build artex-security from this reviewed checkout first.' >&2; exit 1; }
  if [[ -n "$artex_reset_config" ]]; then
    export ARTEX_CONFIG="$artex_reset_config"
  fi
elif [[ -n "$artex_reset_config" ]]; then
  printf '%s\n' 'Docker mode uses the private Compose runtime DSN; --config is only for local mode.' >&2
  exit 2
fi
if [[ "$artex_reset_mode" == docker ]]; then
  # Anchor Compose discovery and its private .env to this deployment, even when
  # invoked by absolute path from another application's directory.
  cd -- "$artex_reset_root"
fi
read -r -s -p 'New administrator password: ' artex_reset_password
printf '\n' >&2
read -r -s -p 'Repeat new password: ' artex_reset_repeat
printf '\n' >&2
[[ "$artex_reset_password" == "$artex_reset_repeat" ]] || { printf '%s\n' 'Passwords do not match.' >&2; exit 1; }
unset artex_reset_repeat
if [[ "$artex_reset_mode" == docker ]]; then
  printf '%s' "$artex_reset_password" | docker compose run --rm --no-deps --interactive -T \
    --entrypoint /app/artex-security artex reset-password --database "$artex_reset_database" --password-stdin --apply
else
  printf '%s' "$artex_reset_password" | "$artex_reset_binary" reset-password --database "$artex_reset_database" --password-stdin --apply
fi
unset artex_reset_password

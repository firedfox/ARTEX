#!/usr/bin/env bash
# The old installer reused a PostgreSQL administrator as the application role.
# This security release supports the explicit Compose/bootstrap/migration flow.
set -euo pipefail
printf '%s\n' 'The legacy one-click installer is paused for the security migration.' >&2
printf '%s\n' 'Use docs/SECURITY_REMEDIATION_20261108.zh-CN.md for the supported secure Compose setup.' >&2
exit 1

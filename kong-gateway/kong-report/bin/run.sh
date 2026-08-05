#!/bin/bash
# Wrapper for cron jobs — load .env then exec python3
# Usage: /opt/csoc-kong-report/bin/run.sh <python-script> [args...]
# Mirrors /opt/csoc-fw-report/run.sh pattern (shared SMTP_PASSWORD env)
set -euo pipefail
cd /opt/csoc-kong-report

if [[ -f .env ]]; then
    set -o allexport
    # shellcheck disable=SC1091
    source ./.env
    set +o allexport
fi

exec python3 "$@"

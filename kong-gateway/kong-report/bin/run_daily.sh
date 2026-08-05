#!/usr/bin/env bash
# /opt/csoc-kong-report/bin/run_daily.sh
#
# Daily orchestrator on kong-gateway-225.
# - Parses yesterday's Kong access + error logs to JSON
# - Ships both JSONs to CT 2065 inbox/YYYY-MM-DD/{access,errors}.json
# Invoked by cron as ssjmuk_admax (NOPASSWD sudo required for log read + /opt write).

set -euo pipefail

BASE=/opt/csoc-kong-report
OUT_DIR="$BASE/out"
LOG_DIR=/var/log/csoc-kong-report
LOCK_FILE=/tmp/csoc-kong-report-run_daily.lock
REMOTE=ssjmuk_admax@10.10.64.65
REMOTE_INBOX=/opt/csoc-kong-report/inbox

DATA_DATE=$(date -d 'yesterday' +%F)
LOG_FILE="$LOG_DIR/run_daily-$(date +%F).log"

if [ ! -d "$LOG_DIR" ]; then
  sudo install -d -m 0755 -o ssjmuk_admax -g ssjmuk_admax "$LOG_DIR"
fi

log() { printf '[%s] %s\n' "$(date +%FT%T%z)" "$*" | tee -a "$LOG_FILE" >&2; }

(
  flock -n 9 || { log "ERR: another run_daily.sh holds lock $LOCK_FILE"; exit 2; }

  log "=== run_daily start data_date=$DATA_DATE host=$(hostname) ==="

  ACCESS_JSON="$OUT_DIR/access-$DATA_DATE.json"
  ERRORS_JSON="$OUT_DIR/errors-$DATA_DATE.json"

  log "sync_kong_routes.py — refresh service_prefix_map.json from Kong admin API"
  # Fail-soft: if Kong API down, parse continues with last-good map (script returns non-zero)
  sudo /usr/bin/python3 "$BASE/bin/sync_kong_routes.py" >>"$LOG_FILE" 2>&1 || \
      log "WARN: sync_kong_routes.py exit non-zero (using stale map for this run)"

  log "parse_access.py --yesterday -> $ACCESS_JSON"
  sudo /usr/bin/python3 "$BASE/bin/parse_access.py" --yesterday --out "$ACCESS_JSON" >>"$LOG_FILE" 2>&1

  log "parse_errors.py --yesterday -> $ERRORS_JSON"
  sudo /usr/bin/python3 "$BASE/bin/parse_errors.py" --yesterday --out "$ERRORS_JSON" >>"$LOG_FILE" 2>&1

  log "ssh mkdir $REMOTE_INBOX/$DATA_DATE on CT 2065"
  ssh -o BatchMode=yes "$REMOTE" "mkdir -p $REMOTE_INBOX/$DATA_DATE" >>"$LOG_FILE" 2>&1

  log "scp access.json + errors.json -> CT 2065"
  scp -o BatchMode=yes "$ACCESS_JSON" "$REMOTE:$REMOTE_INBOX/$DATA_DATE/access.json" >>"$LOG_FILE" 2>&1
  scp -o BatchMode=yes "$ERRORS_JSON" "$REMOTE:$REMOTE_INBOX/$DATA_DATE/errors.json" >>"$LOG_FILE" 2>&1

  ACCESS_SIZE=$(stat -c %s "$ACCESS_JSON")
  ERRORS_SIZE=$(stat -c %s "$ERRORS_JSON")
  log "=== run_daily success access=${ACCESS_SIZE}B errors=${ERRORS_SIZE}B ==="
) 9>"$LOCK_FILE"

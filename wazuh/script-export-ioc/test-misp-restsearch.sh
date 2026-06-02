#!/usr/bin/env bash
# test-misp-restsearch.sh
# Probe MISP /attributes/restSearch endpoint using curl.
# Loads MISP_URL / MISP_API_KEY / MISP_VERIFY_SSL from .env in the same folder.
#
# Usage:
#   ./test-misp-restsearch.sh                                       # GET, ip-src, 300d
#   TYPE=ip-dst DAYS=30 ./test-misp-restsearch.sh
#   METHOD=POST TYPE=sha256 DAYS=30 ./test-misp-restsearch.sh
#   FORMAT=json ./test-misp-restsearch.sh
#   ./test-misp-restsearch.sh out.txt                               # save body to file
#
# Env overrides:
#   METHOD=GET|POST                     (default GET)
#   TYPE=ip-src                         (default ip-src)
#   DAYS=300                            (default 300)
#   FORMAT=text|json|csv                (default text)
#   TO_IDS=1                            (default 1)
#   FILTER_PARAM=attribute_timestamp    (default attribute_timestamp; alternatives:
#                                        publish_timestamp / timestamp / event_timestamp.
#                                        attribute_timestamp filters on the attribute's
#                                        own last-edit time - re-publishing the parent
#                                        event does NOT bump it, so stale IoCs from
#                                        re-published events are excluded.)

set -euo pipefail

# --- Load .env ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ERROR: .env not found at $ENV_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

[[ -n "${MISP_URL:-}" ]]     || { echo "ERROR: MISP_URL not set" >&2; exit 1; }
[[ -n "${MISP_API_KEY:-}" ]] || { echo "ERROR: MISP_API_KEY not set" >&2; exit 1; }

# --- Params ---
METHOD="${METHOD:-GET}"
TYPE="${TYPE:-ip-src}"
DAYS="${DAYS:-300}"
FORMAT="${FORMAT:-text}"
TO_IDS="${TO_IDS:-1}"
FILTER_PARAM="${FILTER_PARAM:-attribute_timestamp}"
SAVE="${1:-}"

BASE="${MISP_URL%/}"

# --- SSL ---
SSL_OPT=()
case "${MISP_VERIFY_SSL,,}" in
    false|0|f|no) SSL_OPT=(-k) ;;
esac

# --- Accept header ---
case "$FORMAT" in
    json) ACCEPT='application/json' ;;
    *)    ACCEPT='text/plain' ;;
esac

# --- Build URL + body ---
if [[ "$METHOD" == "GET" ]]; then
    URL="$BASE/attributes/restSearch/returnFormat:$FORMAT/type:$TYPE/to_ids:$TO_IDS/${FILTER_PARAM}:${DAYS}d"
    BODY_ARGS=()
else
    URL="$BASE/attributes/restSearch"
    BODY=$(printf '{"returnFormat":"%s","type":"%s","to_ids":%s,"%s":"%sd"}' \
                  "$FORMAT" "$TYPE" "$TO_IDS" "$FILTER_PARAM" "$DAYS")
    BODY_ARGS=(-H 'Content-Type: application/json' --data-raw "$BODY")
fi

echo "$METHOD $URL"
echo "verify_ssl=${MISP_VERIFY_SSL:-unset}"
[[ "$METHOD" == "POST" ]] && echo "body: $BODY"
echo "Authorization: ${MISP_API_KEY:0:4}...${MISP_API_KEY: -4}"
echo

# --- Run ---
TMP_BODY=$(mktemp); TMP_HDR=$(mktemp)
trap 'rm -f "$TMP_BODY" "$TMP_HDR"' EXIT

START=$(date +%s%3N)
HTTP_CODE=$(curl -sS -o "$TMP_BODY" -D "$TMP_HDR" -w '%{http_code}' \
    -X "$METHOD" "$URL" \
    -H "Authorization: $MISP_API_KEY" \
    -H "Accept: $ACCEPT" \
    "${SSL_OPT[@]}" "${BODY_ARGS[@]}" \
    --max-time 120) || HTTP_CODE='000'
END=$(date +%s%3N)
ELAPSED=$((END - START))

BYTES=$(wc -c < "$TMP_BODY" | tr -d ' ')
LINES=$(wc -l < "$TMP_BODY" | tr -d ' ')

if [[ "$HTTP_CODE" == "200" ]]; then
    echo "HTTP 200 - ${ELAPSED} ms - ${BYTES} bytes - ${LINES} line(s)"
    echo '---- first 20 lines ----'
    head -n 20 "$TMP_BODY"
    if [[ -n "$SAVE" ]]; then
        cp "$TMP_BODY" "$SAVE"
        echo
        echo "Saved full body to $SAVE"
    fi
else
    echo "FAILED - HTTP $HTTP_CODE - ${ELAPSED} ms" >&2
    echo '---- response body ----' >&2
    head -c 1000 "$TMP_BODY" >&2; echo >&2
    exit 1
fi

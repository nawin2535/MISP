#!/bin/bash
# misp_to_wazuh.sh
# Fetch ip-src + ip-dst from MISP, dedup, write to Wazuh CDB blacklist-ip.
# Loads MISP_URL / MISP_API_KEY / MISP_VERIFY_SSL from .env in this folder
# (matches export_misp_to_wazuh.py behavior).
#
# Time filter (--days N) is applied to BOTH ip-src and ip-dst, matching the
# TIME_FILTERED_TYPES = {ip-src, ip-dst} contract in export_misp_to_wazuh.py.
#
# Usage:
#   ./misp_to_wazuh.sh                   # default 300 days
#   ./misp_to_wazuh.sh --days 30
#   DAYS=90 ./misp_to_wazuh.sh           # env var equivalent
#   ./misp_to_wazuh.sh --days 0          # no time filter (legacy behavior)

set -euo pipefail

# --- CLI / env ---
DAYS="${DAYS:-300}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days) DAYS="$2"; shift 2 ;;
        --days=*) DAYS="${1#*=}"; shift ;;
        -h|--help)
            sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

# --- Load .env from script's folder ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

[[ -n "${MISP_URL:-}" ]]     || { echo "$(date '+%F %T') ERROR: MISP_URL not set (env or .env)" >&2; exit 1; }
[[ -n "${MISP_API_KEY:-}" ]] || { echo "$(date '+%F %T') ERROR: MISP_API_KEY not set (env or .env)" >&2; exit 1; }

# --- SSL: honor MISP_VERIFY_SSL (default False -> -k) ---
SSL_OPT=(-k)
case "${MISP_VERIFY_SSL:-False}" in
    True|true|1|t|yes) SSL_OPT=() ;;
esac

# --- Build URLs (path-style filters, GET) ---
BASE="${MISP_URL%/}"
COMMON_FILTERS="returnFormat:text/to_ids:1"
if [[ "$DAYS" -gt 0 ]]; then
    COMMON_FILTERS="$COMMON_FILTERS/publish_timestamp:${DAYS}d"
fi
URL_SRC="$BASE/attributes/restSearch/$COMMON_FILTERS/type:ip-src"
URL_DST="$BASE/attributes/restSearch/$COMMON_FILTERS/type:ip-dst"

BLACKLIST_FILE="/var/ossec/etc/lists/blacklist-ip"
TMP_FILE="$(mktemp /tmp/blacklist-ip.XXXXXX)"
trap 'rm -f "$TMP_FILE"' EXIT

# --- Fetch helper with HTTP status check ---
fetch_misp() {
    local url="$1" label="$2" out_var="$3"
    local body http_code
    body=$(curl -sS "${SSL_OPT[@]}" -X GET \
        -H "Authorization: $MISP_API_KEY" \
        -H 'Accept: text/plain' \
        -w '\n__HTTP_CODE__:%{http_code}' \
        --max-time 180 \
        "$url") || {
        echo "$(date '+%F %T') ERROR: curl failed for $label" >&2
        return 1
    }
    http_code="${body##*__HTTP_CODE__:}"
    body="${body%$'\n'__HTTP_CODE__:*}"
    if [[ "$http_code" != "200" ]]; then
        echo "$(date '+%F %T') ERROR: MISP $label returned HTTP $http_code" >&2
        echo "  response: $(echo "$body" | head -c 300)" >&2
        return 1
    fi
    printf -v "$out_var" '%s' "$body"
}

window_note=$([[ "$DAYS" -gt 0 ]] && echo "publish_timestamp=${DAYS}d" || echo "no time filter")
echo "$(date '+%F %T') INFO: Fetching ip-src + ip-dst from MISP ($window_note)"

response_src=""; response_dst=""
fetch_misp "$URL_SRC" "ip-src" response_src
fetch_misp "$URL_DST" "ip-dst" response_dst

# --- Process: extract IPv4 lines, append ':' for CDB key-only format ---
{
    printf '%s\n' "$response_src"
    printf '%s\n' "$response_dst"
} | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $0":"}' \
  | sort -u > "$TMP_FILE"

count=$(wc -l < "$TMP_FILE" | tr -d ' ')
if [[ "$count" -eq 0 ]]; then
    echo "$(date '+%F %T') ERROR: 0 IPs after parsing - aborting (refusing to overwrite blacklist with empty file)" >&2
    exit 1
fi

# --- Replace final file + fix perms ---
mv "$TMP_FILE" "$BLACKLIST_FILE"
chown wazuh:wazuh "$BLACKLIST_FILE"
chmod 770 "$BLACKLIST_FILE"

echo "$(date '+%F %T') INFO: Blacklist updated ($count unique IPs, $window_note)"

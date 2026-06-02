#!/bin/bash
# kongblock.sh — block/unblock IP via Kong ip-restriction plugin
# Usage:
#   ./kongblock.sh --ip <IP> --deny   --source misp|behavior|manual [--rule-id N]
#   ./kongblock.sh --ip <IP> --allow  [--source misp|behavior|manual]
#
# --source classification:
#   misp     = IP came from MISP CDB match (rule.id in {100203,100204,100205,100206})
#              → eligible for auto-unblock by reconcile-kong-misp.sh when the
#                MISP IoC ages out (attribute_timestamp > 300d).
#   behavior = IP caught by Wazuh behavioral rules (SQLi probes, 400 spike, SSH
#              brute force, etc.) → NEVER auto-unblocked.
#   manual   = admin-added (for emergency block) → NEVER auto-unblocked.
#
# Two manifest files mirror Kong + firewalld state for the reconcile script:
#   blocked-misp.txt      — auto-managed, append on --deny --source misp
#   blocked-behavior.txt  — auto-managed, append on --deny --source behavior|manual
# --allow removes the IP from BOTH manifests (regardless of caller's --source)
# so the state stays consistent if classification was wrong on the way in.

set -uo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KONG_ADMIN_URL="http://localhost:8001"
PLUGIN_NAME="ip-restriction"
PLUGIN_ID="366a1e31-2aaa-40aa-be4a-5ad27e6ad7c7"   # hardcoded; uncomment find_plugin_id() if recreating Kong plugin
STATUS_CODE=403
MESSAGE="IP is blocked"

TESTBLOCK_FILE="${SCRIPT_DIR}/testblock.txt"
MANIFEST_MISP="${SCRIPT_DIR}/blocked-misp.txt"
MANIFEST_BEHAVIOR="${SCRIPT_DIR}/blocked-behavior.txt"
LOG_FILE="${SCRIPT_DIR}/kongblock.log"
AUDIT_LOG="${SCRIPT_DIR}/kongblock-audit.log"
LOCK_FILE="${SCRIPT_DIR}/.kongblock.lock"
# Per-user tmp file to avoid permission clashes when both root + service user
# invoke kongblock.sh against the same /tmp path.
ERR_FILE="${SCRIPT_DIR}/.kongblock.err.$$"
trap 'rm -f "$ERR_FILE"' EXIT

# --- Helpers ---
log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') $1" >> "$LOG_FILE"
}

audit() {
    # TSV: timestamp \t action \t ip \t source \t rule_id \t result
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds)" "$1" "$2" "$3" "$4" "$5" >> "$AUDIT_LOG"
}

usage() {
    echo "Usage: $0 --ip <IP> --deny --source misp|behavior|manual [--rule-id N]"
    echo "       $0 --ip <IP> --allow [--source misp|behavior|manual]"
    exit 2
}

command -v curl >/dev/null 2>&1 || { echo "Error: curl is required"; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "Error: jq is required"; exit 1; }
command -v flock >/dev/null 2>&1 || { echo "Error: flock is required"; exit 1; }

# --- Parse args ---
IP_ADDRESS=""; ACTION=""; SOURCE=""; RULE_ID=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)       IP_ADDRESS="$2"; shift 2 ;;
        --allow)    ACTION="allow"; shift ;;
        --deny)     ACTION="deny";  shift ;;
        --source)   SOURCE="$2";    shift 2 ;;
        --rule-id)  RULE_ID="$2";   shift 2 ;;
        -h|--help)  usage ;;
        *)          usage ;;
    esac
done

[[ -z "$IP_ADDRESS" || -z "$ACTION" ]] && usage

if [[ "$ACTION" == "deny" && -z "$SOURCE" ]]; then
    echo "Error: --deny requires --source misp|behavior|manual" >&2
    log "Error: --deny without --source for IP $IP_ADDRESS"
    exit 2
fi

if [[ -n "$SOURCE" && "$SOURCE" != "misp" && "$SOURCE" != "behavior" && "$SOURCE" != "manual" ]]; then
    echo "Error: --source must be misp|behavior|manual (got: $SOURCE)" >&2
    exit 2
fi

# --- Ensure manifest files exist ---
touch "$MANIFEST_MISP" "$MANIFEST_BEHAVIOR" "$TESTBLOCK_FILE" "$AUDIT_LOG"

# --- Kong API helpers ---
get_plugin_config() {
    local pid="$1"
    curl -sS -X GET "$KONG_ADMIN_URL/plugins/$pid" 2>"$ERR_FILE" | jq ".config"
}

update_plugin() {
    local pid="$1" current_cfg="$2" ip="$3" action="$4"
    local allow_list deny_list payload response

    allow_list=$(echo "$current_cfg" | jq -r ".allow // []")
    deny_list=$(echo "$current_cfg"  | jq -r ".deny  // []")

    if [[ "$action" == "allow" ]]; then
        deny_list=$(echo "$deny_list" | jq --arg ip "$ip" 'map(select(. != $ip))')
    else
        if echo "$deny_list" | jq -e --arg ip "$ip" 'index($ip)' >/dev/null; then
            log "IP $ip already in deny list — skipping Kong API"
            return 0
        fi
        deny_list=$(echo "$deny_list" | jq --arg ip "$ip" '. + [$ip]')
    fi

    payload=$(jq -n \
        --arg name "$PLUGIN_NAME" \
        --argjson allow "$allow_list" \
        --argjson deny "$deny_list" \
        --arg status "$(echo "$current_cfg" | jq -r ".status // \"$STATUS_CODE\"")" \
        --arg message "$(echo "$current_cfg" | jq -r ".message // \"$MESSAGE\"")" \
        '{name: $name, config: {allow: $allow, deny: $deny, status: ($status | tonumber), message: $message}}')

    response=$(curl -sS -X PATCH "$KONG_ADMIN_URL/plugins/$pid" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>"$ERR_FILE")

    if echo "$response" | jq -e ".id" >/dev/null 2>&1; then
        log "Kong plugin updated: $ip $action"
        return 0
    else
        log "ERROR Kong API: $response | $(cat "$ERR_FILE" 2>/dev/null)"
        return 1
    fi
}

# --- Manifest helpers (with flock) ---
manifest_add() {
    local file="$1" ip="$2"
    (
        flock -x 200
        if ! grep -Fx "$ip" "$file" >/dev/null 2>&1; then
            echo "$ip" >> "$file"
        fi
    ) 200>"$LOCK_FILE"
}

manifest_remove() {
    local file="$1" ip="$2"
    (
        flock -x 200
        if grep -Fx "$ip" "$file" >/dev/null 2>&1; then
            sed -i "/^${ip//./\\.}$/d" "$file"
        fi
    ) 200>"$LOCK_FILE"
}

# --- Main ---
config=$(get_plugin_config "$PLUGIN_ID")
if [[ -z "$config" || "$config" == "null" ]]; then
    log "ERROR: failed to fetch plugin config for $PLUGIN_ID"
    audit "$ACTION" "$IP_ADDRESS" "${SOURCE:-?}" "${RULE_ID:-?}" "config_fetch_failed"
    exit 1
fi

if ! update_plugin "$PLUGIN_ID" "$config" "$IP_ADDRESS" "$ACTION"; then
    audit "$ACTION" "$IP_ADDRESS" "${SOURCE:-?}" "${RULE_ID:-?}" "kong_api_failed"
    exit 1
fi

# Update manifests + testblock mirror
if [[ "$ACTION" == "deny" ]]; then
    case "$SOURCE" in
        misp)              manifest_add "$MANIFEST_MISP" "$IP_ADDRESS" ;;
        behavior|manual)   manifest_add "$MANIFEST_BEHAVIOR" "$IP_ADDRESS" ;;
    esac
    manifest_add "$TESTBLOCK_FILE" "$IP_ADDRESS"
else
    # --allow: remove from BOTH manifests + testblock (clean regardless of caller's --source)
    manifest_remove "$MANIFEST_MISP"     "$IP_ADDRESS"
    manifest_remove "$MANIFEST_BEHAVIOR" "$IP_ADDRESS"
    manifest_remove "$TESTBLOCK_FILE"    "$IP_ADDRESS"
fi

audit "$ACTION" "$IP_ADDRESS" "${SOURCE:-?}" "${RULE_ID:-?}" "ok"
echo "IP $IP_ADDRESS $ACTION (source=${SOURCE:-?})"
exit 0

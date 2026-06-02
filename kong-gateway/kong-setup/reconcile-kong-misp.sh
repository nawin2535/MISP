#!/bin/bash
# reconcile-kong-misp.sh — sync Kong + firewalld block state with MISP feed.
#
# Pulls IPs directly from MISP REST API (same pattern as misp_to_wazuh.sh on
# wazuh-manager). For IPs in blocked-misp.txt that are no longer in the MISP
# response (= MISP IoC aged out beyond attribute_timestamp:300d), unblock them
# from BOTH Kong's ip-restriction plugin AND firewalld rich-rules.
#
# blocked-behavior.txt is NEVER touched - those IPs were blocked by Wazuh
# behavioral rules (SQLi probes, brute force, etc.) and stay blocked.
#
# Usage:
#   ./reconcile-kong-misp.sh                 # apply unblocks
#   ./reconcile-kong-misp.sh --dry-run       # show diff, do not apply
#   ./reconcile-kong-misp.sh --bootstrap     # one-shot: split current state
#                                            #   into misp vs behavior manifests
#                                            #   by intersecting with MISP feed
#
# Env overrides (or pass via .env):
#   MISP_URL / MISP_API_KEY / MISP_VERIFY_SSL  - MISP credentials (required)
#   DAYS=300                                   - attribute_timestamp window
#   THRESHOLD=1000                             - refuse if MISP returned < N IPs
#                                                (guard against feed corruption)

set -uo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KONGBLOCK_SH="${SCRIPT_DIR}/kongblock.sh"
MANIFEST_MISP="${SCRIPT_DIR}/blocked-misp.txt"
MANIFEST_BEHAVIOR="${SCRIPT_DIR}/blocked-behavior.txt"
LOG_FILE="${SCRIPT_DIR}/reconcile.log"
AUDIT_LOG="${SCRIPT_DIR}/kongblock-audit.log"
LOCK_FILE="${SCRIPT_DIR}/.reconcile.lock"
ENV_FILE="${SCRIPT_DIR}/.env"

# --- Args ---
DRY_RUN=0
BOOTSTRAP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=1; shift ;;
        --bootstrap) BOOTSTRAP=1; shift ;;
        -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

# --- Logging ---
log() {
    local msg="$1"
    echo "$(date '+%Y/%m/%d %H:%M:%S') $msg" | tee -a "$LOG_FILE"
}

audit() {
    # TSV: timestamp \t action \t ip \t source \t rule_id \t result
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds)" "$1" "$2" "$3" "$4" "$5" >> "$AUDIT_LOG"
}

# --- Lock (prevent concurrent reconcile) ---
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log "Another reconcile is running (lock held); exiting."
    exit 0
fi

# --- Load .env ---
if [[ -f "$ENV_FILE" ]]; then
    if [[ ! -r "$ENV_FILE" ]]; then
        log "ERROR: $ENV_FILE exists but is not readable by $(id -un) (uid=$(id -u))"
        log "       fix: sudo chown $(id -un):$(id -gn) $ENV_FILE && sudo chmod 600 $ENV_FILE"
        exit 1
    fi
    set -a; # shellcheck disable=SC1090
    source "$ENV_FILE"; set +a
else
    log "WARN: $ENV_FILE not found - falling back to environment variables"
fi

[[ -n "${MISP_URL:-}" ]]     || { log "ERROR: MISP_URL not set (check .env or env vars)";     exit 1; }
[[ -n "${MISP_API_KEY:-}" ]] || { log "ERROR: MISP_API_KEY not set (check .env or env vars)"; exit 1; }

DAYS="${DAYS:-300}"
THRESHOLD="${THRESHOLD:-1000}"

# --- Dependencies ---
for cmd in curl jq awk sort comm flock firewall-cmd; do
    command -v "$cmd" >/dev/null 2>&1 || { log "ERROR: $cmd is required"; exit 1; }
done

# firewall-cmd needs root or polkit auth. If we're not root, prefix sudo.
# Requires /etc/sudoers.d/kong-reconcile granting NOPASSWD: /usr/bin/firewall-cmd
SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo -n"
    if ! $SUDO firewall-cmd --state >/dev/null 2>&1; then
        log "ERROR: cannot run 'sudo firewall-cmd' without password"
        log "       fix: add to /etc/sudoers.d/kong-reconcile:"
        log "       $(id -un) ALL=(root) NOPASSWD: /usr/bin/firewall-cmd"
        exit 1
    fi
fi

# --- SSL flag ---
SSL_OPT=(-k)
case "${MISP_VERIFY_SSL:-False}" in
    True|true|1|t|yes) SSL_OPT=() ;;
esac

touch "$MANIFEST_MISP" "$MANIFEST_BEHAVIOR" "$AUDIT_LOG"

# --- Fetch MISP IPs (ip-src + ip-dst, attribute_timestamp:Nd) ---
fetch_misp_ips() {
    local label="$1" url="$2"
    local body http_code
    body=$(curl -sS "${SSL_OPT[@]}" -X GET \
        -H "Authorization: $MISP_API_KEY" \
        -H 'Accept: text/plain' \
        -w '\n__HTTP_CODE__:%{http_code}' \
        --max-time 180 "$url") || {
        log "ERROR: curl failed for $label"
        return 1
    }
    http_code="${body##*__HTTP_CODE__:}"
    body="${body%$'\n'__HTTP_CODE__:*}"
    if [[ "$http_code" != "200" ]]; then
        log "ERROR: MISP $label returned HTTP $http_code"
        log "  response (truncated): $(echo "$body" | head -c 300)"
        return 1
    fi
    echo "$body"
}

BASE="${MISP_URL%/}"
COMMON="returnFormat:text/to_ids:1/attribute_timestamp:${DAYS}d"

log "Reconcile start (dry_run=$DRY_RUN bootstrap=$BOOTSTRAP days=$DAYS threshold=$THRESHOLD)"

resp_src=$(fetch_misp_ips "ip-src" "$BASE/attributes/restSearch/$COMMON/type:ip-src") || exit 1
resp_dst=$(fetch_misp_ips "ip-dst" "$BASE/attributes/restSearch/$COMMON/type:ip-dst") || exit 1

# Build authoritative MISP set (IPv4-only — matches misp_to_wazuh.sh contract)
MISP_SET="$(mktemp)"
trap 'rm -f "$MISP_SET" "$MISP_SET".kong "$MISP_SET".fw "$MISP_SET".tu' EXIT

{
    printf '%s\n' "$resp_src"
    printf '%s\n' "$resp_dst"
} | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $0}' \
  | sort -u > "$MISP_SET"

misp_count=$(wc -l < "$MISP_SET" | tr -d ' ')
log "MISP returned $misp_count unique IPv4 addresses"

# --- Threshold guard: refuse if MISP responded with suspiciously few IPs ---
if [[ "$misp_count" -lt "$THRESHOLD" ]]; then
    log "ABORT: MISP returned $misp_count IPs < threshold $THRESHOLD (feed corruption suspected). State unchanged."
    audit "reconcile-abort" "-" "misp" "-" "below_threshold:$misp_count"
    exit 1
fi

# ============================================================
# BOOTSTRAP MODE: derive manifests from current Kong + firewalld
# ============================================================
if [[ "$BOOTSTRAP" -eq 1 ]]; then
    log "Bootstrap: classifying current blocks into misp/behavior manifests"

    # Pull current Kong deny[]
    KONG_DENY="$(mktemp)"
    curl -sS "http://localhost:8001/plugins/366a1e31-2aaa-40aa-be4a-5ad27e6ad7c7" \
        | jq -r '.config.deny[]?' \
        | sort -u > "$KONG_DENY" || { log "ERROR: failed to read Kong plugin"; exit 1; }

    # Pull current firewalld rich-rule drops (IPv4 only)
    FW_DROP="$(mktemp)"
    $SUDO firewall-cmd --list-rich-rules 2>/dev/null \
        | grep 'family="ipv4"' \
        | grep 'drop' \
        | sed -E 's/.*source address="([0-9.]+)".*/\1/' \
        | sort -u > "$FW_DROP" || true
    fw_count=$(wc -l < "$FW_DROP" | tr -d ' ')
    log "Bootstrap: firewalld rich-rules drop count = $fw_count"

    # Union: every IP that's blocked anywhere
    CURRENT_BLOCKS="$(mktemp)"
    cat "$KONG_DENY" "$FW_DROP" | sort -u > "$CURRENT_BLOCKS"
    block_count=$(wc -l < "$CURRENT_BLOCKS" | tr -d ' ')
    log "Bootstrap: $block_count IPs currently blocked (Kong + firewalld union)"

    # Split: IP in current_blocks AND in misp_feed -> misp_manifest
    # Split: IP in current_blocks AND NOT in misp_feed -> behavior_manifest
    if [[ "$DRY_RUN" -eq 1 ]]; then
        new_misp_count=$(comm -12 "$CURRENT_BLOCKS" "$MISP_SET" | wc -l)
        new_behavior_count=$(comm -23 "$CURRENT_BLOCKS" "$MISP_SET" | wc -l)
        log "Bootstrap DRY-RUN: would write blocked-misp.txt=$new_misp_count blocked-behavior.txt=$new_behavior_count"
    else
        # Sanity check the lock file BEFORE the subshell so failure is loud
        # (otherwise a permission-denied on fd 201 would silently skip the
        # comm writes and we would log "APPLIED" with stale counts).
        if ! ( : >> "${SCRIPT_DIR}/.kongblock.lock" ) 2>/dev/null; then
            log "ERROR: cannot write to ${SCRIPT_DIR}/.kongblock.lock (perm denied?). Aborting."
            log "       fix: sudo rm -f ${SCRIPT_DIR}/.kongblock.lock && sudo chown -R $(id -un):$(id -gn) ${SCRIPT_DIR}"
            audit "bootstrap" "-" "-" "-" "lock_file_unwritable"
            exit 1
        fi

        if ! (
            flock -x 201
            comm -12 "$CURRENT_BLOCKS" "$MISP_SET" > "$MANIFEST_MISP"
            comm -23 "$CURRENT_BLOCKS" "$MISP_SET" > "$MANIFEST_BEHAVIOR"
        ) 201>"${SCRIPT_DIR}/.kongblock.lock"; then
            log "ERROR: bootstrap write failed (subshell exit non-zero). Manifests unchanged."
            audit "bootstrap" "-" "-" "-" "write_failed"
            exit 1
        fi

        new_misp_count=$(wc -l < "$MANIFEST_MISP" | tr -d ' ')
        new_behavior_count=$(wc -l < "$MANIFEST_BEHAVIOR" | tr -d ' ')
        log "Bootstrap APPLIED: blocked-misp.txt=$new_misp_count blocked-behavior.txt=$new_behavior_count"
        audit "bootstrap" "-" "-" "-" "misp=$new_misp_count behavior=$new_behavior_count"
    fi
    rm -f "$KONG_DENY" "$FW_DROP" "$CURRENT_BLOCKS"
    exit 0
fi

# ============================================================
# NORMAL MODE: unblock IPs that have aged out of MISP
# ============================================================
misp_sorted="$(mktemp)"; cp "$MISP_SET" "$misp_sorted"
misp_manifest_sorted="$(mktemp)"; sort -u "$MANIFEST_MISP" > "$misp_manifest_sorted"
behavior_sorted="$(mktemp)"; sort -u "$MANIFEST_BEHAVIOR" > "$behavior_sorted"

# to_unblock = misp_manifest - misp_feed
#            (then subtract behavior_manifest to be extra safe — if user
#             manually tagged an IP as behavior, never unblock even if also in misp_manifest)
TO_UNBLOCK="$(mktemp)"
comm -23 "$misp_manifest_sorted" "$misp_sorted" \
  | comm -23 - "$behavior_sorted" \
  > "$TO_UNBLOCK"

unblock_count=$(wc -l < "$TO_UNBLOCK" | tr -d ' ')
manifest_count=$(wc -l < "$misp_manifest_sorted" | tr -d ' ')
log "blocked-misp.txt has $manifest_count IPs; $unblock_count have aged out of MISP"

rm -f "$misp_sorted" "$misp_manifest_sorted" "$behavior_sorted"

if [[ "$unblock_count" -eq 0 ]]; then
    log "Nothing to unblock — exiting."
    exit 0
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: would unblock the following $unblock_count IP(s):"
    head -n 50 "$TO_UNBLOCK" | sed 's/^/  /' | tee -a "$LOG_FILE"
    [[ "$unblock_count" -gt 50 ]] && log "  ... and $((unblock_count - 50)) more"
    exit 0
fi

# --- Apply unblocks ---
success=0; failed=0
while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue

    # 1. Kong unblock + manifest cleanup
    if "$KONGBLOCK_SH" --ip "$ip" --allow --source misp >>"$LOG_FILE" 2>&1; then
        :
    else
        log "WARN: kongblock.sh --allow failed for $ip"
        audit "reconcile-unblock" "$ip" "misp" "-" "kong_failed"
        ((failed++))
        continue
    fi

    # 2. firewalld remove rich-rule (best-effort — runtime only here, batched permanent at end)
    if $SUDO firewall-cmd --remove-rich-rule="rule family=\"ipv4\" source address=\"$ip\" drop" >/dev/null 2>&1; then
        :
    else
        # Not fatal — IP may not have had a firewalld rule
        log "INFO: no firewalld rich-rule for $ip (already removed?)"
    fi

    audit "reconcile-unblock" "$ip" "misp" "-" "ok"
    ((success++))
done < "$TO_UNBLOCK"

# --- Batch persist firewalld changes once at the end ---
if [[ "$success" -gt 0 ]]; then
    $SUDO firewall-cmd --runtime-to-permanent >>"$LOG_FILE" 2>&1 || log "WARN: runtime-to-permanent failed"
    $SUDO firewall-cmd --reload                >>"$LOG_FILE" 2>&1 || log "WARN: firewall reload failed"
fi

log "Reconcile done: unblocked=$success failed=$failed"
audit "reconcile-end" "-" "misp" "-" "unblocked=$success failed=$failed"
exit 0

#!/usr/bin/env python3
"""Sync Kong admin API -> service_prefix_map.json (dynamic, no manual edit).

Runs on kong-225 before parse_access.py via run_daily.sh cron.
Fetches /routes + /services from Kong admin API, derives service+category
from prefix patterns (MoPH conventions in CATEGORY_RULES below), and
atomically overwrites /opt/csoc-kong-report/etc/service_prefix_map.json.

Why dynamic:
  - Multiple Kong admins adjust routes constantly
  - Static map drift causes S1 service_breakdown to mislabel new routes
    as "catchall" → false negative ใน threat hunting

Fail-safe:
  - If Kong API down/non-200 → keep existing map (no overwrite)
  - Atomic temp+rename → never leave map in half-written state
  - Logs to /var/log/csoc-kong-report/route_sync-YYYY-MM-DD.log

Category rules (CATEGORY_RULES): first match wins, ordered by specificity.
Update only when MoPH adds a NEW app convention (e.g., a new prefix family).
This is the only manually-maintained piece — but updates < 1x/year typically.
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

KONG_ADMIN = os.environ.get("KONG_ADMIN_URL", "http://localhost:8001")
ROOT = Path(os.environ.get("CSOC_KONG_ROOT", "/opt/csoc-kong-report"))
OUTPUT = ROOT / "etc" / "service_prefix_map.json"
LOG_DIR = Path("/var/log/csoc-kong-report")

# Category derivation rules — first regex.match() wins
CATEGORY_RULES = [
    (r"^/csoc-anomaly-dashboard",                                       "csoc"),
    (r"^/auth(/|$)",                                                    "auth-sensitive"),
    (r"^/computer(/|$)",                                                "computer-portal"),
    (r"^/calendar(/|$)|^/healthatlas|^/docsys|^/claimmuk|^/assets(/|$)","computer-portal"),
    (r"^/web1|^/fda|^/mukpao|^/muksmartncd|^/inventory",                "computer-portal"),
    (r"^/e-office-data|^/e-reserv-car|^/timebanker|^/academic|^/cockpit","moph-host"),
    (r"^/archives|^/linenotify|^/rxmuk|^/localllm|^/hdc-ai|^/_next(/|$)","internal-tool"),
    (r"^/patient-tracking|^/zzjmukcyberseclab|^/pentest|^/pdpa",         "internal-tool"),
    (r"^/dev_|^/develop-|^/msq-health|^/assetAuthenUi|^/certificate",   "internal-tool"),
    (r"^/$",                                                            "catchall"),
    (r".*",                                                             "cms-web"),  # default
]


def derive_category(prefix: str) -> str:
    for pat, cat in CATEGORY_RULES:
        if re.match(pat, prefix):
            return cat
    return "unknown"


def derive_service_name(prefix: str) -> str:
    """Derive logical service label from prefix — granular per app.

    Kong's actual service name often groups multiple apps under one service
    (e.g., 'mukweb' service handles /mukweb, /mukcovid, /pms2023, /smartmom, ...).
    For SOC reporting we want per-prefix granularity:
      /mukweb                          -> mukweb
      /computer/web51v2                -> computer-web51v2
      /csoc-anomaly-dashboard/admin-training -> csoc-anomaly-dashboard-admin-training
      /                                -> catchall
    """
    if prefix == "/":
        return "catchall"
    return prefix.lstrip("/").rstrip("/").replace("/", "-")


def fetch_json(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"GET {url} -> HTTP {resp.status}")
        return json.loads(resp.read())


def log(msg: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    line = f"[{time.strftime('%FT%T%z')}] {msg}\n"
    sys.stderr.write(line)
    log_file = LOG_DIR / f"route_sync-{time.strftime('%F')}.log"
    with open(log_file, "a") as f:
        f.write(line)


def main() -> int:
    log(f"=== sync_kong_routes start kong_admin={KONG_ADMIN} ===")
    try:
        routes_resp = fetch_json(f"{KONG_ADMIN}/routes?size=1000")
        svc_resp = fetch_json(f"{KONG_ADMIN}/services?size=1000")
    except Exception as e:
        log(f"ERR Kong API fetch failed: {e} — keep existing map (no overwrite)")
        return 1  # exit non-zero but cron continues to parse with stale map

    svc_by_id = {s["id"]: s.get("name") or "unnamed" for s in svc_resp.get("data", [])}

    prefixes = []
    seen = set()  # dedupe by prefix
    for route in routes_resp.get("data", []):
        svc_id = (route.get("service") or {}).get("id") or ""
        kong_svc = svc_by_id.get(svc_id, "unknown")
        route_name = route.get("name") or ""
        for raw in (route.get("paths") or []):
            # normalize: strip trailing slash except root
            prefix = raw if raw == "/" else raw.rstrip("/")
            if prefix in seen:
                continue
            seen.add(prefix)
            prefixes.append({
                "prefix": prefix,
                "service": derive_service_name(prefix),
                "category": derive_category(prefix),
                "kong_service": kong_svc,   # actual Kong service (debug only)
                "kong_route": route_name,   # actual Kong route name (debug only)
            })

    # Longest-prefix-wins → sort by prefix length DESC for service_map.py
    prefixes.sort(key=lambda p: len(p["prefix"]), reverse=True)

    # Diff vs previous (for log + visibility)
    prev_prefixes = set()
    if OUTPUT.exists():
        try:
            prev = json.load(open(OUTPUT))
            prev_prefixes = {p["prefix"] for p in prev.get("prefixes", [])}
        except Exception:
            pass
    cur_prefixes = {p["prefix"] for p in prefixes}
    added = cur_prefixes - prev_prefixes
    removed = prev_prefixes - cur_prefixes
    if added:
        log(f"NEW prefixes ({len(added)}): {sorted(added)}")
    if removed:
        log(f"REMOVED prefixes ({len(removed)}): {sorted(removed)}")
    if not added and not removed:
        log(f"no drift — {len(prefixes)} prefixes unchanged")

    out = {
        "_meta": {
            "generated_from": f"kong admin api {KONG_ADMIN}/routes + /services",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "match_policy": "longest-prefix-wins",
            "category_source": "derived from CATEGORY_RULES in sync_kong_routes.py",
            "drift_since_last": {"added": sorted(added), "removed": sorted(removed)},
        },
        "prefixes": prefixes,
    }

    # Atomic write
    tmp = OUTPUT.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    os.replace(tmp, OUTPUT)
    log(f"wrote {OUTPUT}: {len(prefixes)} prefixes (added={len(added)} removed={len(removed)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

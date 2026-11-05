"""Smoke test for the read-only MISP key used by the Wazuh CDB export.

Reads the key from KEY_FILE on this host (never printed) and MISP_URL from .env next to this script.
Usage on wazuh-server (root, venv python):
  venv/bin/python3 misp_key_smoke.py                          # 5 checks on the key
  venv/bin/python3 misp_key_smoke.py --value 1.2.3.4          # + that IoC must be visible in MISP
  venv/bin/python3 misp_key_smoke.py --value 1.2.3.4 --cdb    # + must be in the CDB lists (after refresh)
Exit 0 = all PASS.
"""
import argparse
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import requests  # noqa: E402
import urllib3  # noqa: E402
from dotenv import dotenv_values  # noqa: E402

urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.environ.get("MISP_API_KEY_FILE", "/etc/misp-export/wazuh-export.SECRET")
# MDO-MOPH owns the ThreatFox events (the feed scheduler user moved to org 51 on 5 Aug 2026)
EXPECT_ORG = "51"
CDB_LISTS = ("/var/ossec/etc/lists/misp_ip-dst", "/var/ossec/etc/lists/blacklist-ip")

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}".rstrip())


def attr_count(resp):
    if not resp.ok:
        return -1
    return len(resp.json().get("response", {}).get("Attribute", []))


def in_list(path, value):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return any(line.startswith(value + ":") or line.startswith(f'"{value}":') for line in fh)
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description="Smoke test the read-only MISP key for Wazuh export")
    ap.add_argument("--value", help="IoC value that must be visible (e.g. a recent ThreatFox IP)")
    ap.add_argument("--cdb", action="store_true", help="also require --value in the Wazuh CDB lists")
    args = ap.parse_args()

    base = (dotenv_values(os.path.join(HERE, ".env")).get("MISP_URL") or "").rstrip("/")
    if not base or not os.path.isfile(KEY_FILE):
        print("FAIL setup: MISP_URL in .env or key file missing")
        return 1
    with open(KEY_FILE, encoding="utf-8") as fh:
        key = fh.read().strip()

    s = requests.Session()
    s.verify = False
    s.headers.update({"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"})

    u = s.get(f"{base}/users/view/me", timeout=30)
    user = u.json().get("User", {}) if u.ok else {}
    check("whoami org", str(user.get("org_id")) == EXPECT_ORG,
          f"http={u.status_code} user_id={user.get('id')} org_id={user.get('org_id')}")

    r = s.post(f"{base}/attributes/restSearch", timeout=60, json={
        "type": "ip-dst|port", "to_ids": 1, "attribute_timestamp": "3d", "limit": 5, "returnFormat": "json"})
    n = attr_count(r)
    check("recent ThreatFox ip-dst|port visible (3d)", n > 0, f"http={r.status_code} got={n}")

    t = s.get(f"{base}/attributes/restSearch/returnFormat:text/to_ids:1/attribute_timestamp:300d/type:ip-dst%7Cport",
              headers={"Accept": "text/plain"}, timeout=180)
    lines = sum(1 for ln in t.text.splitlines() if "|" in ln) if t.ok else -1
    check("text GET ip-dst|port 300d (misp_to_wazuh.sh path)", lines > 0, f"http={t.status_code} lines={lines}")

    try:
        from pymisp import PyMISP
        res = PyMISP(base, key, ssl=False).search(
            controller="attributes", type_attribute=["ip-dst", "ip-dst|port"], to_ids=1, limit=5, page=1)
        got = len(res.get("Attribute", [])) if isinstance(res, dict) else len(res)
        check("PyMISP POST restSearch (export_misp_to_wazuh.py path)", got > 0, f"got={got}")
    except Exception as exc:  # report, keep going
        check("PyMISP POST restSearch (export_misp_to_wazuh.py path)", False, type(exc).__name__)

    # Event id that cannot exist: a refused write creates nothing, an accepted one fails with 404 instead
    w = s.post(f"{base}/attributes/add/999999999", json={"type": "comment", "value": "read-only smoke"}, timeout=30)
    check("key is read-only (write refused)", w.status_code in (401, 403, 405), f"http={w.status_code}")

    if args.value:
        n = attr_count(s.post(f"{base}/attributes/restSearch", timeout=60,
                              json={"value": args.value, "returnFormat": "json"}))
        check(f"value {args.value} visible", n > 0, f"got={n}")
        if args.cdb:
            hit = [os.path.basename(p) for p in CDB_LISTS if in_list(p, args.value)]
            check(f"value {args.value} in CDB", bool(hit), ",".join(hit) or "none")

    ok = all(results)
    print(f"SUMMARY {'PASS' if ok else 'FAIL'} ({sum(results)}/{len(results)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""Smoke test for the read-only MISP key used by the Wazuh CDB export.

Reads the key from KEY_FILE on this host (never printed) and MISP_URL from .env next to this script.
Usage on wazuh-server (root, venv python):
  venv/bin/python3 misp_key_smoke.py                          # 5 checks on the key
  venv/bin/python3 misp_key_smoke.py --value 1.2.3.4          # + that IoC must be visible in MISP
  venv/bin/python3 misp_key_smoke.py --value 1.2.3.4 --cdb    # + must be in the CDB lists (after refresh)
  venv/bin/python3 misp_key_smoke.py --quick --cdb            # SOAR probe (hourly): 3 key checks + ThreatFox
                                                              #   sample in each CDB list
Exit 0 = all PASS, 1 = a check failed, 2 = MISP unreachable (connection error / timeout / 5xx).
"""
import argparse
import os
import re
import sys
import time
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
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

results = []


class Unreachable(Exception):
    pass


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}".rstrip())


def req(s, method, url, timeout, **kw):
    """Transport errors and 5xx say nothing about the key -> Unreachable (exit 2), not FAIL."""
    try:
        r = s.request(method, url, timeout=timeout, **kw)
    except requests.RequestException as exc:
        raise Unreachable(type(exc).__name__) from None
    if r.status_code >= 500:
        raise Unreachable(f"http={r.status_code} {url[len(s.base):]}")
    return r


def attrs(resp):
    if not resp.ok:
        return None
    try:
        return resp.json().get("response", {}).get("Attribute", [])
    except ValueError:
        return None


def attr_count(resp):
    got = attrs(resp)
    return -1 if got is None else len(got)


def in_list(path, value):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return any(line.startswith(value + ":") or line.startswith(f'"{value}":') for line in fh)
    except OSError:
        return False


def list_keys(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return {ln.split(":", 1)[0].strip('"') for ln in fh}
    except OSError:
        return None


def cdb_sample(s, base):
    """ThreatFox IoC published before a list was written must be in that list -- each list on its own:
    blacklist-ip alone hid that misp_ip-dst never got ip-dst|port (fixed 5 Nov 2026)."""
    for path in CDB_LISTS:
        name = os.path.basename(path)
        keys = list_keys(path)
        if keys is None:
            check(f"CDB {name} readable", False)
            continue
        mtime = int(os.path.getmtime(path))
        when = time.strftime("%m-%d %H:%M", time.localtime(mtime))
        # Filter on the event publish time (when MISP took it in): attribute timestamps are ThreatFox's own and
        # run up to ~25h before the 07:35 fetch, so comparing them with the list mtime gives false misses
        r = req(s, "POST", f"{base}/attributes/restSearch", 60, json={
            "type": "ip-dst|port", "to_ids": 1, "publish_timestamp": [mtime - 4 * 86400, mtime - 900],
            "limit": 50, "returnFormat": "json"})
        got = attrs(r)
        if got is None:
            check(f"ThreatFox sample in {name}", False, f"http={r.status_code}")
            continue
        ips = [a["value"].split("|")[0] for a in got]
        ips = [ip for ip in ips if IPV4.match(ip)]
        if not ips:
            print(f"SKIP ThreatFox sample in {name}: nothing published in the 4 days before {when}")
            continue
        ev = sorted(int(a["event_id"]) for a in got)
        hit = sum(ip in keys for ip in ips)
        check(f"ThreatFox sample in {name}", hit * 10 >= len(ips) * 9,
              f"{hit}/{len(ips)} ev={ev[0]}-{ev[-1]} list={when}")


def run(s, base, args):
    u = req(s, "GET", f"{base}/users/view/me", 20)
    try:
        user = u.json().get("User", {}) if u.ok else {}
    except ValueError:
        user = {}
    check("whoami org", str(user.get("org_id")) == EXPECT_ORG,
          f"http={u.status_code} user_id={user.get('id')} org_id={user.get('org_id')}")

    r = req(s, "POST", f"{base}/attributes/restSearch", 30, json={
        "type": "ip-dst|port", "to_ids": 1, "attribute_timestamp": "3d", "limit": 5, "returnFormat": "json"})
    n = attr_count(r)
    check("recent ThreatFox ip-dst|port visible (3d)", n > 0, f"http={r.status_code} got={n}")

    if not args.quick:
        t = req(s, "GET", f"{base}/attributes/restSearch/returnFormat:text/to_ids:1/attribute_timestamp:300d"
                "/type:ip-dst%7Cport", 180, headers={"Accept": "text/plain"})
        lines = sum(1 for ln in t.text.splitlines() if "|" in ln) if t.ok else -1
        check("text GET ip-dst|port 300d (misp_to_wazuh.sh path)", lines > 0, f"http={t.status_code} lines={lines}")

        try:
            from pymisp import PyMISP
            res = PyMISP(base, s.headers["Authorization"], ssl=False).search(
                controller="attributes", type_attribute=["ip-dst", "ip-dst|port"], to_ids=1, limit=5, page=1)
            got = len(res.get("Attribute", [])) if isinstance(res, dict) else len(res)
            check("PyMISP POST restSearch (export_misp_to_wazuh.py path)", got > 0, f"got={got}")
        except Exception as exc:  # report, keep going
            check("PyMISP POST restSearch (export_misp_to_wazuh.py path)", False, type(exc).__name__)

    # Event id that cannot exist: a refused write creates nothing, an accepted one fails with 404 instead
    w = req(s, "POST", f"{base}/attributes/add/999999999", 20, json={"type": "comment", "value": "read-only smoke"})
    check("key is read-only (write refused)", w.status_code in (401, 403, 405), f"http={w.status_code}")

    if args.value:
        n = attr_count(req(s, "POST", f"{base}/attributes/restSearch", 60,
                           json={"value": args.value, "returnFormat": "json"}))
        check(f"value {args.value} visible", n > 0, f"got={n}")
        if args.cdb:
            hit = [os.path.basename(p) for p in CDB_LISTS if in_list(p, args.value)]
            check(f"value {args.value} in CDB", bool(hit), ",".join(hit) or "none")
    if args.cdb:
        cdb_sample(s, base)


def main():
    ap = argparse.ArgumentParser(description="Smoke test the read-only MISP key for Wazuh export")
    ap.add_argument("--value", help="IoC value that must be visible (e.g. a recent ThreatFox IP)")
    ap.add_argument("--cdb", action="store_true",
                    help="also sample recent ThreatFox IPs in each CDB list (+ --value if given)")
    ap.add_argument("--quick", action="store_true", help="skip the two heavy export-path checks (300d pulls)")
    args = ap.parse_args()

    base = (dotenv_values(os.path.join(HERE, ".env")).get("MISP_URL") or "").rstrip("/")
    if not base or not os.path.isfile(KEY_FILE):
        print("FAIL setup: MISP_URL in .env or key file missing")
        return 1
    with open(KEY_FILE, encoding="utf-8") as fh:
        key = fh.read().strip()

    s = requests.Session()
    s.verify = False
    s.base = base
    s.headers.update({"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"})

    try:
        run(s, base, args)
    except Unreachable as exc:
        print(f"ERROR MISP unreachable: {exc}")
        print(f"SUMMARY ERROR ({sum(results)}/{len(results)} passed before the error)")
        return 2
    ok = all(results)
    print(f"SUMMARY {'PASS' if ok else 'FAIL'} ({sum(results)}/{len(results)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

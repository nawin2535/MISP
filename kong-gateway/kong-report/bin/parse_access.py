#!/usr/bin/env python3
"""parse_access.py - Kong access log -> daily JSON summary (Phase 2).

Adds on top of Phase 1:
  - URI path normalization (etc/path_normalize.json)
  - Service/category lookup via Kong route prefix map (etc/service_prefix_map.json)
  - Sqlite first-seen baseline (state/known_baseline.db) for "new IP / new path" flags

Usage:
  parse_access.py <log-file>
  parse_access.py --yesterday                 # auto-pick today's rotated .gz
  parse_access.py <log-file> --out FILE
  parse_access.py <log-file> --report-date YYYY-MM-DD
  parse_access.py <log-file> --no-baseline    # skip baseline read/write
  parse_access.py --init-baseline N           # backfill last N days then exit
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Import siblings — bin/ is on PYTHONPATH when invoked as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_map import ServiceMap          # noqa: E402
from path_norm import PathNormalizer        # noqa: E402
from baseline import Baseline               # noqa: E402
from query_anomaly import QueryAnomalyScanner  # noqa: E402

DEFAULT_LOG_DIR = Path("/var/log")
DEFAULT_LOG_PREFIX = "kong-docker.log-"
DEFAULT_ROOT = Path("/opt/csoc-kong-report")

LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s+'
    r'"(?P<ref>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
    r'(?:\s+kong_request_id:\s+"(?P<rid>[^"]*)")?'
)
TS_FMT = "%d/%b/%Y:%H:%M:%S %z"
TOP_N = 50


def open_log(path: Path):
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def bucket_status(code: int) -> str:
    return f"{code // 100}xx"


def parse_file(path: Path, norm: PathNormalizer, smap: ServiceMap,
               scanner: QueryAnomalyScanner) -> dict:
    t0 = time.time()
    total = parsed = malformed = 0
    status_codes = Counter()
    status_buckets = Counter()
    methods = Counter()
    src_ips = Counter()
    bytes_by_ip = Counter()
    top_paths = Counter()
    top_paths_raw = Counter()
    top_uas = Counter()
    by_hour = Counter()
    total_bytes = 0
    auth_fail_by_ip = defaultdict(Counter)

    # Cross-dimension correlation collectors (for ip_footprint / path_reach / quiet_combos)
    path_ip_count: dict[str, Counter] = defaultdict(Counter)     # path -> ip -> count
    ip_method_count: dict[str, Counter] = defaultdict(Counter)   # ip -> method -> count
    ip_status_count: dict[str, Counter] = defaultdict(Counter)   # ip -> status_bucket -> count
    ip_path_count: dict[str, Counter] = defaultdict(Counter)     # ip -> path -> count
    path_status_count: dict[str, Counter] = defaultdict(Counter) # path -> status_bucket -> count
    combo_count: Counter = Counter()                              # (ip, method, path, status_code) -> count
    combo_bytes: dict = defaultdict(int)                          # same key -> sum bytes

    # Service / category aggregates
    svc_req = Counter()
    svc_bytes = Counter()
    svc_status = defaultdict(Counter)       # service -> {"2xx": n, ...}
    svc_category: dict[str, str] = {}       # service -> category
    svc_prefix: dict[str, str] = {}         # service -> longest matched prefix seen
    cat_req = Counter()
    cat_bytes = Counter()
    cat_services: dict[str, set] = defaultdict(set)
    catchall_paths = Counter()              # raw URIs that fell into the "/" catchall

    # Query/URI anomaly aggregates
    sig_counts = Counter()                  # category -> count (attacks)
    sig_by_ip = defaultdict(Counter)        # ip -> {category: n}
    sig_samples: list[dict] = []            # bounded list of evidence rows
    SIG_SAMPLE_CAP = 200                    # keep cap small; renderer picks top-N
    # Sanctioned scanner traffic (whitelisted) tracked separately
    scanner_traffic_counts = Counter()
    scanner_traffic_by_ip = defaultdict(Counter)

    first_ts = None
    last_ts = None

    with open_log(path) as f:
        for line in f:
            total += 1
            m = LINE_RE.match(line)
            if not m:
                malformed += 1
                continue
            parsed += 1
            g = m.groupdict()
            ip = g["ip"]
            code = int(g["status"])
            bk = bucket_status(code)
            method = g["method"]
            raw_uri = g["uri"]
            uri = norm.apply(raw_uri)
            ua = g["ua"] or "-"
            blen = 0 if g["bytes"] == "-" else int(g["bytes"])

            status_codes[code] += 1
            status_buckets[bk] += 1
            methods[method] += 1
            src_ips[ip] += 1
            bytes_by_ip[ip] += blen
            top_paths[uri] += 1
            top_paths_raw[raw_uri] += 1
            top_uas[ua] += 1
            total_bytes += blen
            if code in (401, 403):
                auth_fail_by_ip[ip][code] += 1

            # service lookup happens on RAW uri (prefixes match raw, not normalized)
            hit = smap.lookup(raw_uri)
            svc_req[hit.service] += 1
            svc_bytes[hit.service] += blen
            svc_status[hit.service][bk] += 1
            svc_category[hit.service] = hit.category
            # Keep the longest matched prefix per service (most-specific representative)
            cur_pfx = svc_prefix.get(hit.service, "")
            if len(hit.matched_prefix) > len(cur_pfx):
                svc_prefix[hit.service] = hit.matched_prefix
            cat_req[hit.category] += 1
            cat_bytes[hit.category] += blen
            cat_services[hit.category].add(hit.service)
            if hit.service == "catchall":
                catchall_paths[raw_uri] += 1

            # Cross-dimension correlation updates
            path_ip_count[uri][ip] += 1
            ip_method_count[ip][method] += 1
            ip_status_count[ip][bk] += 1
            ip_path_count[ip][uri] += 1
            path_status_count[uri][bk] += 1
            combo_key = (ip, method, uri, code)
            combo_count[combo_key] += 1
            combo_bytes[combo_key] += blen

            sig_hits = scanner.scan(raw_uri)
            if sig_hits:
                whitelisted = scanner.is_whitelisted(ip)
                for cat_name, sev in sig_hits:
                    if whitelisted:
                        scanner_traffic_counts[cat_name] += 1
                        scanner_traffic_by_ip[ip][cat_name] += 1
                    else:
                        sig_counts[cat_name] += 1
                        sig_by_ip[ip][cat_name] += 1
                if not whitelisted and len(sig_samples) < SIG_SAMPLE_CAP:
                    sig_samples.append({
                        "ip": ip,
                        "ts": g["ts"],
                        "method": method,
                        "uri": raw_uri[:300],
                        "status": code,
                        "categories": [c for c, _ in sig_hits],
                        "severity": max((s for _, s in sig_hits),
                                        key=lambda x: {"high": 3, "medium": 2, "low": 1}.get(x, 0)),
                    })

            try:
                dt = datetime.strptime(g["ts"], TS_FMT)
                by_hour[dt.hour] += 1
                if first_ts is None or dt < first_ts:
                    first_ts = dt
                if last_ts is None or dt > last_ts:
                    last_ts = dt
            except ValueError:
                pass

    auth_fail_summary = sorted(
        ({"ip": ip, "401": c.get(401, 0), "403": c.get(403, 0), "total": sum(c.values())}
         for ip, c in auth_fail_by_ip.items()),
        key=lambda r: r["total"], reverse=True,
    )[:TOP_N]

    service_breakdown = sorted(
        (
            {
                "service": svc,
                "category": svc_category.get(svc, "unknown"),
                "prefix": svc_prefix.get(svc, "-"),
                "requests": svc_req[svc],
                "bytes": svc_bytes[svc],
                "status": dict(sorted(svc_status[svc].items())),
            }
            for svc in svc_req
        ),
        key=lambda r: r["requests"], reverse=True,
    )

    # ───── Cross-dimension sections ─────
    # A. IP Footprint — top 30 IPs with profile (S3 hot zone)
    ip_footprint = []
    for ip, total in src_ips.most_common(30):
        methods_for_ip = ip_method_count[ip]
        statuses = ip_status_count[ip]
        ip_footprint.append({
            "ip": ip,
            "requests": total,
            "distinct_paths": len(ip_path_count[ip]),
            "bytes_out": bytes_by_ip[ip],
            "top_method": methods_for_ip.most_common(1)[0][0] if methods_for_ip else "-",
            "status_2xx": statuses.get("2xx", 0),
            "status_3xx": statuses.get("3xx", 0),
            "status_4xx": statuses.get("4xx", 0),
            "status_5xx": statuses.get("5xx", 0),
            "top_paths": [{"path": p, "count": c}
                          for p, c in ip_path_count[ip].most_common(3)],
        })

    # B1. High-reach paths — top 30 by request count, show distinct_ips
    path_reach_high = []
    top_30_paths_set = set()
    for path, count in top_paths.most_common(30):
        top_30_paths_set.add(path)
        statuses = path_status_count[path]
        path_reach_high.append({
            "path": path,
            "requests": count,
            "distinct_ips": len(path_ip_count[path]),
            "dominant_status": statuses.most_common(1)[0][0] if statuses else "-",
        })

    # B1b. Path Long Tail (S3b) — paths rank 31+, group by URL, show ALL IPs that called
    # User feedback 2026-06-27 v5:
    #   - keep singletons (count=1) — "1 IP + 1 path + 1 hit = แปลกที่สุด" (probe ครั้งเดียวไม่ repeat)
    #   - sort alphabetical by path → group same-prefix together (/smartmom/*, /web1/*)
    #   - cap 1000 cover rank 31+ ครบทั้งหมด (~1016 paths/day typical)
    path_long_tail_candidates = []
    for path, count in top_paths.most_common():
        if path in top_30_paths_set:
            continue
        statuses = path_status_count[path]
        ips_counter = path_ip_count[path]
        # solo_ip_global_paths = ถ้า path นี้มี IP เดียวยิง, IP นั้น touched กี่ paths ทั้งวัน
        # ใช้แยก 1-HIT-ISO (IP probe path เดียวจริงๆ) vs 1-HIT-browse (IP touches many paths)
        solo_ip = next(iter(ips_counter)) if len(ips_counter) == 1 else None
        solo_ip_global_paths = len(ip_path_count[solo_ip]) if solo_ip else None
        one_hit = (count == 1 and len(ips_counter) == 1)
        path_long_tail_candidates.append({
            "path": path,
            "requests": count,
            "distinct_ips": len(ips_counter),
            "dominant_status": statuses.most_common(1)[0][0] if statuses else "-",
            "status_2xx": statuses.get("2xx", 0),
            "status_3xx": statuses.get("3xx", 0),
            "status_4xx": statuses.get("4xx", 0),
            "status_5xx": statuses.get("5xx", 0),
            "ips": [{"ip": ip, "count": c} for ip, c in ips_counter.most_common()],
            "one_hit": one_hit,
            "solo_ip_global_paths": solo_ip_global_paths,
            "one_hit_iso": (one_hit and solo_ip_global_paths is not None and solo_ip_global_paths <= 2),
        })
    # Alpha sort by path → scan by prefix
    path_long_tail = sorted(
        path_long_tail_candidates,
        key=lambda r: r["path"],
    )[:1000]

    # B2. Rare-but-successful paths — distinct_ips==1, count>=2, dominant 2xx
    rare_2xx_paths = []
    for path, count in top_paths.most_common():
        if count < 2:
            break  # Counter is sorted DESC, no more candidates
        if len(path_ip_count[path]) != 1:
            continue
        statuses = path_status_count[path]
        if not statuses or statuses.most_common(1)[0][0] != "2xx":
            continue
        only_ip = next(iter(path_ip_count[path]))
        rare_2xx_paths.append({
            "path": path,
            "requests": count,
            "ip": only_ip,
        })
        if len(rare_2xx_paths) >= 20:
            break

    # C. Quiet Combos candidates — 2xx + path NOT in top-100 + (rare OR is_new_ip [filled later])
    # IP newness flag is filled in apply_baseline(); pre-build candidates here.
    top_100_paths_set = {p for p, _ in top_paths.most_common(100)}
    rare_path_set = {p for p, ipc in path_ip_count.items() if len(ipc) == 1}

    quiet_combos_candidates = []
    for (ip, method, path, status_code), cnt in combo_count.most_common():
        if not (200 <= status_code < 300):
            continue
        if path in top_100_paths_set:
            continue
        is_rare = path in rare_path_set
        quiet_combos_candidates.append({
            "ip": ip,
            "method": method,
            "path": path,
            "status": status_code,
            "count": cnt,
            "bytes": combo_bytes[(ip, method, path, status_code)],
            "is_rare_path": is_rare,
            "is_new_ip": False,  # filled by apply_baseline
        })
        if len(quiet_combos_candidates) >= 200:  # cap before final filter
            break

    category_breakdown = sorted(
        (
            {
                "category": cat,
                "requests": cat_req[cat],
                "bytes": cat_bytes[cat],
                "services": len(cat_services[cat]),
            }
            for cat in cat_req
        ),
        key=lambda r: r["requests"], reverse=True,
    )

    # Top IPs by anomaly count (sum across categories)
    top_anomaly_ips = sorted(
        ({"ip": ip, "total": sum(cnts.values()), **dict(cnts)} for ip, cnts in sig_by_ip.items()),
        key=lambda r: r["total"], reverse=True,
    )[:TOP_N]

    elapsed = round(time.time() - t0, 3)

    return {
        "source_file": str(path),
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "totals": {
            "lines": total,
            "parsed": parsed,
            "malformed": malformed,
            "bytes_sent": total_bytes,
            "unique_src_ips": len(src_ips),
            "unique_paths_raw": len(top_paths_raw),
            "unique_paths_normalized": len(top_paths),
            "unique_user_agents": len(top_uas),
            "elapsed_sec": elapsed,
        },
        "status_buckets": dict(sorted(status_buckets.items())),
        "status_codes_top": dict(status_codes.most_common(20)),
        "methods": dict(methods.most_common()),
        "by_hour": [by_hour.get(h, 0) for h in range(24)],
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in src_ips.most_common(TOP_N)],
        "top_bytes_out_ips": [{"ip": ip, "bytes": b} for ip, b in bytes_by_ip.most_common(TOP_N)],
        "top_paths": [{"path": p, "count": c} for p, c in top_paths.most_common(TOP_N)],
        "top_user_agents": [{"ua": u, "count": c} for u, c in top_uas.most_common(TOP_N)],
        "auth_fail_top": auth_fail_summary,
        "service_breakdown": service_breakdown,
        "category_breakdown": category_breakdown,
        "catchall_paths_top": [{"path": p, "count": c} for p, c in catchall_paths.most_common(TOP_N)],
        "ip_footprint": ip_footprint,
        "path_long_tail": path_long_tail,
        "path_reach": {
            "high_reach": path_reach_high,
            "rare_2xx": rare_2xx_paths,
        },
        "_quiet_combos_candidates": quiet_combos_candidates,
        "request_param_anomaly": {
            "by_category": dict(sig_counts),
            "total_hits": sum(sig_counts.values()),
            "unique_ips": len(sig_by_ip),
            "top_ips": top_anomaly_ips,
            "samples": sig_samples,
        },
        "scanner_traffic": {
            "by_category": dict(scanner_traffic_counts),
            "total_hits": sum(scanner_traffic_counts.values()),
            "by_ip": {ip: dict(c) for ip, c in scanner_traffic_by_ip.items()},
            "note": "sanctioned internal scanners (whitelist_ips in query_signatures.json). "
                    "Listed for verification, NOT counted as attacks.",
        },
        # for baseline classification (kept out of public sections)
        "_all_src_ips": list(src_ips.keys()),
        "_all_norm_paths": list(top_paths.keys()),
        "_path_counts": dict(top_paths),
        "_ip_counts": dict(src_ips),
        "_ip_bytes": dict(bytes_by_ip),
    }


def apply_baseline(summary: dict, baseline: Baseline, report_date: str) -> None:
    """Classify new IPs/paths against 30d baseline, then upsert today's data."""
    ips = summary.pop("_all_src_ips")
    paths = summary.pop("_all_norm_paths")
    p_counts = summary.pop("_path_counts")
    i_counts = summary.pop("_ip_counts")
    i_bytes = summary.pop("_ip_bytes")

    new_ips_r = baseline.classify_new_ips(ips, report_date, lookback_days=30, warmup_days=7)
    new_paths_r = baseline.classify_new_paths(paths, report_date, lookback_days=30, warmup_days=7)

    new_ip_rows = sorted(
        (
            {"ip": ip, "requests": i_counts.get(ip, 0), "bytes": i_bytes.get(ip, 0)}
            for ip in new_ips_r.new_items
        ),
        key=lambda r: r["requests"], reverse=True,
    )[:TOP_N]

    new_path_rows = sorted(
        (
            {"path": p, "requests": p_counts.get(p, 0)}
            for p in new_paths_r.new_items
        ),
        key=lambda r: r["requests"], reverse=True,
    )[:TOP_N]

    summary["new_ips"] = {
        "warming_up": new_ips_r.warming_up,
        "baseline_days": new_ips_r.baseline_days,
        "lookback_days": 30,
        "count": len(new_ips_r.new_items),
        "top": new_ip_rows,
    }
    summary["new_paths"] = {
        "warming_up": new_paths_r.warming_up,
        "baseline_days": new_paths_r.baseline_days,
        "lookback_days": 30,
        "count": len(new_paths_r.new_items),
        "top": new_path_rows,
    }

    # Quiet Combos final filter — combine rare-path criterion (set in parser) with is_new_ip flag
    candidates = summary.pop("_quiet_combos_candidates", [])
    new_ip_set = set(new_ips_r.new_items)
    quiet_combos = []
    for c in candidates:
        c["is_new_ip"] = c["ip"] in new_ip_set
        if c["is_rare_path"] or c["is_new_ip"]:
            quiet_combos.append(c)
        if len(quiet_combos) >= 30:
            break
    summary["quiet_combos"] = {
        "rows": quiet_combos,
        "criteria": "status=2xx AND path NOT in top-100 AND (path has only 1 distinct IP OR IP is new vs baseline)",
        "warming_up_note": ("Baseline warming up — is_new_ip flag noisy until >=7 days seeded"
                            if new_ips_r.warming_up else None),
    }

    baseline.upsert(ips, paths, report_date)
    summary["baseline_stats"] = baseline.stats()


def pick_yesterday_file() -> Path:
    """Logrotate at 00:00 stamps new .gz with today's date; that file holds yesterday's data."""
    today = datetime.now()
    return DEFAULT_LOG_DIR / f"{DEFAULT_LOG_PREFIX}{today.strftime('%Y%m%d')}.gz"


def report_date_for_file(path: Path) -> str:
    """Derive ISO report_date from rotated filename suffix (-YYYYMMDD.gz)."""
    m = re.search(r"-(\d{8})\.gz$", path.name)
    if m:
        d = datetime.strptime(m.group(1), "%Y%m%d") - timedelta(days=1)
        return d.date().isoformat()
    return (datetime.now() - timedelta(days=1)).date().isoformat()


def init_baseline(n_days: int, log_dir: Path, baseline: Baseline,
                  norm: PathNormalizer, smap: ServiceMap,
                  scanner: QueryAnomalyScanner) -> None:
    """Backfill baseline by scanning last N rotated files. Idempotent."""
    today = datetime.now()
    seeded = 0
    for i in range(1, n_days + 1):
        d = today - timedelta(days=i - 1)
        f = log_dir / f"{DEFAULT_LOG_PREFIX}{d.strftime('%Y%m%d')}.gz"
        if not f.exists():
            print(f"  skip (missing): {f.name}", file=sys.stderr)
            continue
        rd = report_date_for_file(f)
        s = parse_file(f, norm, smap, scanner)
        baseline.upsert(s["_all_src_ips"], s["_all_norm_paths"], rd)
        print(f"  seeded {f.name}: ips={len(s['_all_src_ips'])} paths={len(s['_all_norm_paths'])} as {rd}",
              file=sys.stderr)
        seeded += 1
    print(f"baseline init done: {seeded} day(s) seeded. {baseline.stats()}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Kong access log -> JSON summary")
    ap.add_argument("path", nargs="?", help="rotated log file (.gz or plain)")
    ap.add_argument("--yesterday", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--report-date", help="override report date (YYYY-MM-DD)")
    ap.add_argument("--root", default=str(DEFAULT_ROOT),
                    help=f"project root (default {DEFAULT_ROOT})")
    ap.add_argument("--no-baseline", action="store_true",
                    help="skip baseline classify+upsert (testing only)")
    ap.add_argument("--init-baseline", type=int, metavar="N",
                    help="backfill baseline from last N rotated files, then exit")
    ap.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    args = ap.parse_args()

    root = Path(args.root)
    smap = ServiceMap.load(root / "etc" / "service_prefix_map.json")
    norm = PathNormalizer.load(root / "etc" / "path_normalize.json")
    scanner = QueryAnomalyScanner.load(root / "etc" / "query_signatures.json")
    baseline = Baseline(root / "state" / "known_baseline.db")

    if args.init_baseline:
        init_baseline(args.init_baseline, Path(args.log_dir), baseline, norm, smap, scanner)
        return

    if args.yesterday:
        path = pick_yesterday_file()
    elif args.path:
        path = Path(args.path)
    else:
        ap.error("provide <path>, --yesterday, or --init-baseline N")

    if not path.exists():
        print(f"ERROR: not found: {path}", file=sys.stderr)
        sys.exit(2)

    report_date = args.report_date or report_date_for_file(path)
    summary = parse_file(path, norm, smap, scanner)
    summary["report_date"] = report_date

    if args.no_baseline:
        for k in ("_all_src_ips", "_all_norm_paths", "_path_counts", "_ip_counts", "_ip_bytes"):
            summary.pop(k, None)
        # Build quiet_combos with rare-path criterion only (no IP newness available)
        candidates = summary.pop("_quiet_combos_candidates", [])
        rare_only = [c for c in candidates if c["is_rare_path"]][:30]
        summary["quiet_combos"] = {
            "rows": rare_only,
            "criteria": "status=2xx AND path NOT in top-100 AND path has only 1 distinct IP "
                        "(baseline skipped: no IP newness signal)",
            "warming_up_note": "baseline disabled (--no-baseline)",
        }
    else:
        apply_baseline(summary, baseline, report_date)

    out = json.dumps(summary, ensure_ascii=False,
                     indent=2 if args.pretty else None,
                     separators=(",", ": ") if args.pretty else (",", ":"))
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote {args.out} ({len(out):,} bytes)", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()

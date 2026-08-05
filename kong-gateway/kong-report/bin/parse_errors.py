#!/usr/bin/env python3
"""parse_errors.py - Kong nginx error log -> JSON summary.

Nginx error format:
  YYYY/MM/DD HH:MM:SS [level] pid#tid: [*connid] <message>[, key: value ...]

Aggregates:
  - by_level (info/notice/warn/error/crit/alert/emerg)
  - by_pattern (message templated: IPs, temp paths, hex ids normalized)
  - bucketed semantic groups (backend down, timeout, ip-restriction block, etc.)
  - top client IPs, top upstreams (host:port), top requests

Usage mirrors parse_access.py:
  parse_errors.py <log-file>
  parse_errors.py --yesterday
  parse_errors.py <log-file> --out FILE
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

DEFAULT_LOG_DIR = Path("/var/log")
DEFAULT_LOG_PREFIX = "docker-kong-errors.log-"
TOP_N = 50
SAMPLE_CAP = 100

# Header: timestamp [level] pid#tid: [optional *connid]
HEADER_RE = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s*'
    r'(?:\*(?P<connid>\d+)\s+)?'
    r'(?P<body>.*)$'
)
TS_FMT = "%Y/%m/%d %H:%M:%S"

# Split body at the first ", client: " — that's where the kv metadata starts.
# Message can itself contain commas (e.g. "(2: No such file or directory)") so a
# simple comma split would break.
BODY_SPLIT_RE = re.compile(r',\s+(?=(?:client|server|request|upstream|host|referrer|request_id):\s)')

# kv pair: key: "quoted value" OR key: bareval
KV_RE = re.compile(r'(?P<key>\w+):\s+(?:"(?P<qval>[^"]*)"|(?P<bval>[^,]+))')

# Normalization rules for message templating (collapse dynamic substrings)
NORM_RULES = [
    (re.compile(r'/usr/local/kong/proxy_temp/\S+'),        '<temp_file>'),
    (re.compile(r'\b\d+\.\d+\.\d+\.\d+(?::\d+)?\b'),       '<ip>'),
    (re.compile(r'\*\d+'),                                  '*<connid>'),
    (re.compile(r'\b0x[0-9a-f]+\b'),                       '<hex>'),
    (re.compile(r'\b[0-9a-f]{16,}\b'),                     '<hash>'),
    (re.compile(r'(?<=:)\d+(?=\W|$)'),                     '<n>'),  # ports/numbers after colons
]

# Semantic buckets — first match wins. Keep keys human-readable for the report.
SEMANTIC_BUCKETS = [
    ("backend_connect_refused",  re.compile(r'connect\(\) failed.*Connection refused', re.I)),
    ("backend_connect_failed",   re.compile(r'connect\(\) failed', re.I)),
    ("upstream_timeout",         re.compile(r'upstream timed out', re.I)),
    ("upstream_prematurely_closed", re.compile(r'upstream prematurely closed', re.I)),
    ("upstream_response_buffered",  re.compile(r'upstream response is buffered to a temporary file', re.I)),
    ("ip_restriction_block",     re.compile(r'IP address not allowed', re.I)),
    ("ssl_handshake_failed",     re.compile(r'SSL_do_handshake\(\) failed', re.I)),
    ("client_too_large_body",    re.compile(r'client intended to send too large body', re.I)),
    ("rewrite_redir_cycle",      re.compile(r'rewrite or internal redirection cycle', re.I)),
    ("file_not_found",           re.compile(r'(?:open\(\) ".*" failed.*No such file|is not found)', re.I)),
    ("client_close_keepalive",   re.compile(r'client \S+ closed keepalive connection', re.I)),
    ("client_close_waiting",     re.compile(r'client closed connection while waiting', re.I)),
    ("client_ssl_handshake_abort", re.compile(r'client closed connection while SSL handshaking', re.I)),
    ("client_request_timeout",   re.compile(r'client timed out.*while waiting for request', re.I)),
    ("client_reset_connection",  re.compile(r'client prematurely closed connection|recv\(\).*reset', re.I)),
]


def open_log(path: Path):
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def normalize_message(msg: str) -> str:
    out = msg
    for pat, repl in NORM_RULES:
        out = pat.sub(repl, out)
    return out


def bucketize(msg: str) -> str:
    for name, pat in SEMANTIC_BUCKETS:
        if pat.search(msg):
            return name
    return "other"


def split_message_and_kv(body: str) -> tuple[str, dict]:
    parts = BODY_SPLIT_RE.split(body, maxsplit=1)
    msg = parts[0].strip()
    kv: dict[str, str] = {}
    if len(parts) > 1:
        # parts[1] starts with "key: ..., key: ..."; iter through KV regex
        rest = parts[1]
        # Also need to split the rest by the same boundary to get individual kv segments
        for seg in BODY_SPLIT_RE.split(", " + rest):
            seg = seg.strip().lstrip(",").strip()
            m = KV_RE.match(seg)
            if m:
                kv[m.group("key")] = m.group("qval") if m.group("qval") is not None else (m.group("bval") or "").strip()
    return msg, kv


def upstream_host_port(upstream: str) -> str:
    """Strip URL down to scheme://host:port for grouping."""
    m = re.match(r'(\w+://[^/]+)', upstream or "")
    return m.group(1) if m else (upstream or "")


def request_method_path(req: str) -> str:
    """'GET /foo?bar=1 HTTP/1.1' -> 'GET /foo'."""
    parts = (req or "").split(" ", 2)
    if len(parts) >= 2:
        path = parts[1].split("?", 1)[0]
        return f"{parts[0]} {path}"
    return req or ""


def parse_file(path: Path) -> dict:
    t0 = time.time()
    total = parsed = malformed = 0
    levels = Counter()
    patterns = Counter()           # normalized message -> count
    buckets = Counter()            # semantic bucket -> count
    by_hour = Counter()
    clients = Counter()
    upstreams = Counter()
    requests = Counter()
    bucket_samples: dict[str, list[dict]] = defaultdict(list)
    by_bucket_clients: dict[str, Counter] = defaultdict(Counter)
    first_ts = None
    last_ts = None

    with open_log(path) as f:
        for line in f:
            total += 1
            line = line.rstrip("\n")
            m = HEADER_RE.match(line)
            if not m:
                malformed += 1
                continue
            parsed += 1
            level = m.group("level")
            body = m.group("body") or ""
            msg, kv = split_message_and_kv(body)
            norm = normalize_message(msg)
            bucket = bucketize(msg)

            levels[level] += 1
            patterns[norm] += 1
            buckets[bucket] += 1

            client = kv.get("client", "").strip()
            if client:
                clients[client] += 1
                by_bucket_clients[bucket][client] += 1
            up = kv.get("upstream", "")
            if up:
                upstreams[upstream_host_port(up)] += 1
            req = kv.get("request", "")
            if req:
                requests[request_method_path(req)] += 1

            if len(bucket_samples[bucket]) < 5:
                bucket_samples[bucket].append({
                    "ts": m.group("ts"),
                    "level": level,
                    "client": client,
                    "request": req[:200],
                    "upstream": (up or "")[:200],
                    "host": kv.get("host", ""),
                    "msg": msg[:300],
                })

            try:
                dt = datetime.strptime(m.group("ts"), TS_FMT)
                by_hour[dt.hour] += 1
                if first_ts is None or dt < first_ts:
                    first_ts = dt
                if last_ts is None or dt > last_ts:
                    last_ts = dt
            except ValueError:
                pass

    bucket_breakdown = sorted(
        (
            {
                "bucket": b,
                "count": buckets[b],
                "top_clients": [{"ip": ip, "count": c}
                                for ip, c in by_bucket_clients[b].most_common(10)],
                "samples": bucket_samples[b],
            }
            for b in buckets
        ),
        key=lambda r: r["count"], reverse=True,
    )

    elapsed = round(time.time() - t0, 3)
    return {
        "source_file": str(path),
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "totals": {
            "lines": total,
            "parsed": parsed,
            "malformed": malformed,
            "elapsed_sec": elapsed,
        },
        "by_level": dict(sorted(levels.items(), key=lambda kv: -kv[1])),
        "by_hour": [by_hour.get(h, 0) for h in range(24)],
        "buckets": bucket_breakdown,
        "top_patterns": [{"pattern": p, "count": c} for p, c in patterns.most_common(TOP_N)],
        "top_clients": [{"ip": ip, "count": c} for ip, c in clients.most_common(TOP_N)],
        "top_upstreams": [{"upstream": u, "count": c} for u, c in upstreams.most_common(TOP_N)],
        "top_requests": [{"request": r, "count": c} for r, c in requests.most_common(TOP_N)],
    }


def pick_yesterday_file() -> Path:
    """Today's date stamp = file containing yesterday's data (same convention as access log)."""
    return DEFAULT_LOG_DIR / f"{DEFAULT_LOG_PREFIX}{datetime.now().strftime('%Y%m%d')}.gz"


def report_date_for_file(path: Path) -> str:
    m = re.search(r"-(\d{8})\.gz$", path.name)
    if m:
        return (datetime.strptime(m.group(1), "%Y%m%d") - timedelta(days=1)).date().isoformat()
    return (datetime.now() - timedelta(days=1)).date().isoformat()


def main():
    ap = argparse.ArgumentParser(description="Kong errors log -> JSON summary")
    ap.add_argument("path", nargs="?")
    ap.add_argument("--yesterday", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--report-date")
    args = ap.parse_args()

    if args.yesterday:
        path = pick_yesterday_file()
    elif args.path:
        path = Path(args.path)
    else:
        ap.error("provide <path> or --yesterday")
    if not path.exists():
        print(f"ERROR: not found: {path}", file=sys.stderr)
        sys.exit(2)

    summary = parse_file(path)
    summary["report_date"] = args.report_date or report_date_for_file(path)
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

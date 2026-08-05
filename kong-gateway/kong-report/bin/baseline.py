"""baseline.py - sqlite-backed first-seen tracker for IPs and normalized paths.

Schema:
  known_ip(ip TEXT PK, first_seen TEXT, last_seen TEXT)
  known_path(path TEXT PK, first_seen TEXT, last_seen TEXT)

Daily flow (called by parse_access.py):
  1. open(db_path)  -> auto-create schema if missing
  2. classify_new_ips(today_ips, report_date, lookback_days=30)
       -> returns list of IPs not seen in the lookback window
  3. classify_new_paths(today_paths, report_date, lookback_days=30)
       -> returns list of paths not seen in the lookback window
  4. upsert(today_ips, today_paths, report_date)
       -> bulk insert/update first_seen+last_seen
  5. prune(max_age_days=400)  -> drop rows untouched > N days (keep db small)

Baseline warm-up: if known_ip has < `warmup_days` distinct first_seen dates,
classify_new returns ([], warming_up=True) so the report can suppress noise.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS known_ip (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_path (
    path TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_last   ON known_ip(last_seen);
CREATE INDEX IF NOT EXISTS idx_path_last ON known_path(last_seen);
"""


@dataclass
class ClassifyResult:
    new_items: list[str]
    warming_up: bool       # True if baseline has too few days to trust
    baseline_days: int     # distinct first_seen dates currently in db (for ip table)


class Baseline:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def _distinct_first_seen_days(self, table: str) -> int:
        with self._conn() as c:
            row = c.execute(f"SELECT COUNT(DISTINCT first_seen) FROM {table}").fetchone()
            return row[0] if row else 0

    def classify_new_ips(self, today_ips: Iterable[str], report_date: str,
                         lookback_days: int = 30, warmup_days: int = 7) -> ClassifyResult:
        return self._classify("known_ip", "ip", today_ips, report_date, lookback_days, warmup_days)

    def classify_new_paths(self, today_paths: Iterable[str], report_date: str,
                           lookback_days: int = 30, warmup_days: int = 7) -> ClassifyResult:
        return self._classify("known_path", "path", today_paths, report_date, lookback_days, warmup_days)

    def _classify(self, table: str, col: str, today: Iterable[str], report_date: str,
                  lookback_days: int, warmup_days: int) -> ClassifyResult:
        baseline_days = self._distinct_first_seen_days(table)
        warming = baseline_days < warmup_days
        today_set = set(today)
        if not today_set:
            return ClassifyResult([], warming, baseline_days)

        cutoff = (datetime.fromisoformat(report_date) - timedelta(days=lookback_days)).date().isoformat()
        with self._conn() as c:
            # Pull only items seen within lookback window
            placeholders = ",".join("?" * len(today_set))
            q = f"SELECT {col} FROM {table} WHERE last_seen >= ? AND {col} IN ({placeholders})"
            rows = c.execute(q, (cutoff, *today_set)).fetchall()
        seen = {r[0] for r in rows}
        new_items = sorted(today_set - seen)
        return ClassifyResult(new_items, warming, baseline_days)

    def upsert(self, ips: Iterable[str], paths: Iterable[str], report_date: str) -> None:
        with self._conn() as c:
            c.executemany(
                "INSERT INTO known_ip(ip, first_seen, last_seen) VALUES (?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen",
                [(ip, report_date, report_date) for ip in set(ips)],
            )
            c.executemany(
                "INSERT INTO known_path(path, first_seen, last_seen) VALUES (?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET last_seen=excluded.last_seen",
                [(p, report_date, report_date) for p in set(paths)],
            )

    def prune(self, max_age_days: int = 400) -> tuple[int, int]:
        cutoff = (datetime.now() - timedelta(days=max_age_days)).date().isoformat()
        with self._conn() as c:
            ip = c.execute("DELETE FROM known_ip WHERE last_seen < ?", (cutoff,)).rowcount
            pp = c.execute("DELETE FROM known_path WHERE last_seen < ?", (cutoff,)).rowcount
        return ip, pp

    def stats(self) -> dict:
        with self._conn() as c:
            ip_cnt = c.execute("SELECT COUNT(*) FROM known_ip").fetchone()[0]
            p_cnt  = c.execute("SELECT COUNT(*) FROM known_path").fetchone()[0]
            ip_days = c.execute("SELECT COUNT(DISTINCT first_seen) FROM known_ip").fetchone()[0]
            p_days  = c.execute("SELECT COUNT(DISTINCT first_seen) FROM known_path").fetchone()[0]
        return {
            "known_ip_count": ip_cnt,
            "known_path_count": p_cnt,
            "ip_distinct_days": ip_days,
            "path_distinct_days": p_days,
        }

"""service_map.py - URI prefix -> Kong service name + category lookup.

Loads etc/service_prefix_map.json once, then provides O(N) longest-prefix
match per URI (N = number of prefixes, ~70). For ~20K req/day that's
~1.4M comparisons — well under a second.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

UNKNOWN_SERVICE = "unknown"
UNKNOWN_CATEGORY = "unknown"


@dataclass(frozen=True)
class ServiceHit:
    service: str
    category: str
    matched_prefix: str


class ServiceMap:
    def __init__(self, entries: list[dict]):
        # sort by prefix length DESC so first match = longest match
        self._entries = sorted(entries, key=lambda e: len(e["prefix"]), reverse=True)

    def lookup(self, uri: str) -> ServiceHit:
        # Boundary-safe match: prefix ending in "/" matches anything below it;
        # bare prefix matches exact OR "/" boundary (so /pms does not match /pms2023).
        # Longest-first ordering ensures /pms2023 wins over /pms when both could match.
        for e in self._entries:
            p = e["prefix"]
            if uri == p:
                return ServiceHit(e["service"], e["category"], p)
            if p.endswith("/"):
                if uri.startswith(p):
                    return ServiceHit(e["service"], e["category"], p)
            else:
                if uri.startswith(p + "/"):
                    return ServiceHit(e["service"], e["category"], p)
        return ServiceHit(UNKNOWN_SERVICE, UNKNOWN_CATEGORY, "")

    @classmethod
    def load(cls, path: Path) -> "ServiceMap":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data["prefixes"])


_DEFAULT: Optional[ServiceMap] = None


def get_default(config_path: Path) -> ServiceMap:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = ServiceMap.load(config_path)
    return _DEFAULT

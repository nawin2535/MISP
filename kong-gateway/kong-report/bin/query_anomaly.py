"""query_anomaly.py - signature-based scan of Kong request URI.

Scope (deliberately narrow): URI field only. Path + query string are URL-decoded
once and tested against compiled regex from etc/query_signatures.json.
Body params, headers, cookies are NOT in default Kong access log and require
the http-log/file-log plugin to capture (privacy + retention review needed
before enabling).

Returns per-line: list of (category, severity) tuples for matched signatures.
One URI matching N patterns in the same category = counted once for that
category (avoids double-counting from overlapping rules).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import unquote


@dataclass(frozen=True)
class Category:
    name: str
    severity: str
    patterns: list[re.Pattern]


class QueryAnomalyScanner:
    def __init__(self, categories: list[Category], whitelist_ips: Optional[set] = None):
        self.categories = categories
        self.whitelist_ips: set = whitelist_ips or set()

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist_ips

    def scan(self, uri: str) -> list[tuple[str, str]]:
        """Return list of (category_name, severity) hits. Empty list = clean."""
        # Decode once. URIs rarely benefit from second-pass decode and
        # double-encoding noise produces false positives.
        try:
            decoded = unquote(uri)
        except Exception:
            decoded = uri
        # Scan both raw (catches %00 literally) and decoded.
        target = decoded if decoded != uri else uri
        hits: list[tuple[str, str]] = []
        for cat in self.categories:
            for pat in cat.patterns:
                if pat.search(target) or (target is not uri and pat.search(uri)):
                    hits.append((cat.name, cat.severity))
                    break  # one hit per category per URI
        return hits

    @classmethod
    def load(cls, path: Path) -> "QueryAnomalyScanner":
        data = json.loads(path.read_text(encoding="utf-8"))
        cats = []
        for c in data["categories"]:
            cats.append(Category(
                name=c["name"],
                severity=c["severity"],
                patterns=[re.compile(p, re.IGNORECASE) for p in c["patterns"]],
            ))
        wl = set(data.get("whitelist_ips", []))
        return cls(cats, whitelist_ips=wl)


_DEFAULT: Optional[QueryAnomalyScanner] = None


def get_default(config_path: Path) -> QueryAnomalyScanner:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = QueryAnomalyScanner.load(config_path)
    return _DEFAULT

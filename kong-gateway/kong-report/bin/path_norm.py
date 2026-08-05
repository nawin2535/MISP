"""path_norm.py - apply regex collapse rules to URI paths.

Normalization keeps /mukpr/uploads/news/abcd.../1234.jpg from exploding
into thousands of unique "paths" in top-N tables. Rules are applied in
declared order; each rule may match multiple times per URI.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    replacement: str


class PathNormalizer:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def apply(self, uri: str) -> str:
        out = uri
        for r in self.rules:
            out = r.pattern.sub(r.replacement, out)
        return out

    @classmethod
    def load(cls, path: Path) -> "PathNormalizer":
        data = json.loads(path.read_text(encoding="utf-8"))
        compiled = [
            Rule(name=r["name"], pattern=re.compile(r["pattern"]), replacement=r["replacement"])
            for r in data["rules"]
        ]
        return cls(compiled)


_DEFAULT: Optional[PathNormalizer] = None


def get_default(config_path: Path) -> PathNormalizer:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = PathNormalizer.load(config_path)
    return _DEFAULT

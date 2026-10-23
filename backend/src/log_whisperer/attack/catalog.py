"""MITRE ATT&CK enterprise technique catalog (built by scripts/build_attack_catalog.py)."""

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

# Enterprise kill-chain order for tables; unknown tactics sort last.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    revoked_by: str | None = None
    deprecated: bool = False


class Catalog:
    def __init__(self, techniques: dict[str, Technique]):
        self.techniques = techniques

    def get(self, tid: str) -> Technique | None:
        return self.techniques.get(tid.upper())

    def resolve(self, tid: str) -> str:
        """Follow revoked-by links to the current technique id."""
        tid, seen = tid.upper(), set()
        while (t := self.techniques.get(tid)) and t.revoked_by and tid not in seen:
            seen.add(tid)
            tid = t.revoked_by
        return tid

    def is_valid(self, tid: str) -> bool:
        return bool(TECHNIQUE_ID.match(tid.upper())) and tid.upper() in self.techniques

    def __len__(self) -> int:
        return len(self.techniques)


def load_catalog(path: Path | None = None) -> Catalog:
    raw = json.loads(Path(path).read_text(encoding="utf-8") if path
                     else files("log_whisperer.attack").joinpath("attack_techniques.json").read_text(encoding="utf-8"))
    return Catalog({tid: Technique(tid, v["name"], tuple(v["tactics"]), v["url"], v.get("revoked_by"),
                                   v.get("deprecated", False)) for tid, v in raw.items()})


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return load_catalog()

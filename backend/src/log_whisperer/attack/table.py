"""Per-incident ATT&CK table: technique rows ordered by kill-chain tactic."""

from collections.abc import Sequence

from pydantic import BaseModel

from log_whisperer.attack.catalog import TACTIC_ORDER, Catalog
from log_whisperer.models import Detection
from log_whisperer.narrative.schema import ValidatedNarrative


class AttackRow(BaseModel):
    tactic: str
    technique_id: str
    name: str
    url: str
    step_indexes: list[int] = []
    detection_ids: list[str] = []


def _tactic_rank(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


def attack_table(narrative: ValidatedNarrative | None, detections: Sequence[Detection],
                 catalog: Catalog) -> list[AttackRow]:
    rows: dict[str, AttackRow] = {}

    def row(tid: str) -> AttackRow | None:
        tid = catalog.resolve(tid)
        t = catalog.get(tid)
        if t is None:
            return None
        if tid not in rows:
            tactic = min(t.tactics, key=_tactic_rank) if t.tactics else "unknown"
            rows[tid] = AttackRow(tactic=tactic, technique_id=tid, name=t.name, url=t.url)
        return rows[tid]

    for d in detections:
        for tid in d.techniques:
            if r := row(tid):
                r.detection_ids.append(d.detection_id)
    if narrative:
        for i, step in enumerate(narrative.steps):
            for tid in step.techniques:
                if r := row(tid):
                    r.step_indexes.append(i)
    return sorted(rows.values(), key=lambda r: (_tactic_rank(r.tactic), r.technique_id))

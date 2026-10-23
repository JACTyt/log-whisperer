"""Narrative quality metrics: citation validity, ATT&CK accuracy, key-fact recall."""

import json
from collections.abc import Iterable, Mapping
from datetime import timedelta

from log_whisperer.evaluation.cases import KeyFact
from log_whisperer.models import Event
from log_whisperer.narrative.schema import ValidatedNarrative

FACT_TS_TOLERANCE = timedelta(minutes=5)


def citation_metrics(nv: ValidatedNarrative) -> dict[str, float]:
    """Share of steps that survived validation, and share not dropped for ungrounded entities."""
    step_rejects = [r for r in nv.rejected if r.index >= 0 and not r.reason.startswith("unknown_technique")]
    total = len(nv.steps) + len(step_rejects)
    if total == 0:
        return {"step_validity": 0.0, "entity_grounding": 0.0}
    ungrounded = sum(1 for r in step_rejects if r.reason.startswith("ungrounded_entity"))
    return {"step_validity": len(nv.steps) / total, "entity_grounding": 1 - ungrounded / total}


def _credit(a: str, b: str) -> float:
    if a == b:
        return 1.0
    return 0.5 if a.split(".")[0] == b.split(".")[0] else 0.0


def technique_metrics(predicted: set[str], expected: set[str]) -> dict[str, float]:
    """Precision/recall where parent vs sub-technique (T1110 vs T1110.001) earns half credit."""
    if not predicted and not expected:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    p = sum(max((_credit(t, e) for e in expected), default=0) for t in predicted) / len(predicted) if predicted else 0.0
    r = sum(max((_credit(e, t) for t in predicted), default=0) for e in expected) / len(expected) if expected else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f1}


def _matches(fact: KeyFact, e: Event) -> bool:
    hay = " ".join(str(v) for v in (e.host, e.user, e.src_ip, e.dst_ip, e.process, e.command_line, e.raw,
                                    json.dumps(e.fields, default=str)) if v).lower()
    if fact.entity.lower() not in hay:
        return False
    if fact.action and e.action != fact.action:
        return False
    if fact.outcome and e.outcome != fact.outcome:
        return False
    return fact.approx_ts is None or abs(e.ts - fact.approx_ts) <= FACT_TS_TOLERANCE


def key_fact_recall(nv: ValidatedNarrative, events_by_id: Mapping[str, Event], facts: Iterable[KeyFact]) -> float:
    facts = list(facts)
    if not facts:
        return 1.0
    cited = [events_by_id[i] for s in nv.steps for i in s.event_ids if i in events_by_id]
    return sum(1 for f in facts if any(_matches(f, e) for e in cited)) / len(facts)

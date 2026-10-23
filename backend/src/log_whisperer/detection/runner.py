"""Run Sigma rules and heuristic detectors, persist new detections."""

import logging
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

import duckdb

from log_whisperer.config import Settings
from log_whisperer.detection.base import Detector
from log_whisperer.detection.sigma_rules import LEVELS, CompiledRule, RuleLoadReport, load_rules
from log_whisperer.models import Detection
from log_whisperer.store import Store

log = logging.getLogger(__name__)
BATCH_RULES = 100


@dataclass
class RunResult:
    detections_new: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)
    rule_report: RuleLoadReport = field(default_factory=RuleLoadReport)
    errors: list[tuple[str, str]] = field(default_factory=list)


def run_sigma(store: Store, rules: Sequence[CompiledRule], since_seq: int | None = None,
              return_errors: bool = False):
    """One detection per matching event. With `return_errors`, returns (detections, errors)."""
    detections: list[Detection] = []
    errors: list[tuple[str, str]] = []
    table = "events"
    if since_seq is not None:  # incremental: evaluate rules over a small copy of just the new events
        table = f"_sigma_scope_{uuid.uuid4().hex[:8]}"
        store.sql(f"CREATE TEMP TABLE {table} AS SELECT * FROM events WHERE seq > ?", [since_seq])
    try:
        # One cheap probe per logsource; rules for event classes that aren't present are skipped.
        present: dict[str, bool] = {}
        for ls in {r.logsource_sql for r in rules}:
            try:
                present[ls] = bool(store.sql(f"SELECT 1 FROM {table} WHERE {ls} LIMIT 1"))
            except duckdb.Error:
                present[ls] = True  # let the per-rule query report the error
        active = [r for r in rules if present[r.logsource_sql]]
        for start in range(0, len(active), BATCH_RULES):
            detections += _run_batch(store, table, active[start:start + BATCH_RULES], errors)
    finally:
        if table != "events":
            store.sql(f"DROP TABLE IF EXISTS {table}")
    if errors:
        log.warning("%d sigma rules failed at query time", len(errors))
    return (detections, errors) if return_errors else detections


def _rule_sql(table: str, rule: CompiledRule, idx: int) -> str:
    return (f'SELECT {idx} AS rule_idx, event_id, ts, host, "user", src_ip FROM {table} '
            f"WHERE ({rule.logsource_sql}) AND ({rule.condition_sql})")


def _run_batch(store: Store, table: str, batch: list[CompiledRule], errors: list[tuple[str, str]]) -> list[Detection]:
    """Many rules in one UNION ALL query (per-query overhead dominates); per-rule fallback on error."""
    try:
        rows = store.sql(" UNION ALL ".join(_rule_sql(table, r, i) for i, r in enumerate(batch)))
    except duckdb.Error:
        rows = []
        for i, rule in enumerate(batch):
            try:
                rows += store.sql(_rule_sql(table, rule, i))
            except duckdb.Error as exc:
                errors.append((rule.title, str(exc).splitlines()[0]))
    by_rule: dict[int, list[tuple]] = {}
    for idx, *rest in rows:
        by_rule.setdefault(idx, []).append(tuple(rest))
    return [d for idx, rs in by_rule.items() for d in _detections(batch[idx], rs)]


def _detections(rule: CompiledRule, rows: list[tuple]) -> list[Detection]:
    return [
        Detection(
            rule_id=rule.rule_id, rule_title=rule.title, rule_source="sigma",
            severity=rule.level, techniques=rule.techniques, event_ids=[event_id],
            ts_first=ts, ts_last=ts,
            hosts=[host] if host else [], users=[user] if user else [], src_ips=[src_ip] if src_ip else [],
        )
        for event_id, ts, host, user, src_ip in rows
    ]


def default_detectors(settings: Settings) -> list[Detector]:
    from log_whisperer.detection.heuristics import default_detectors as heuristics

    return heuristics(settings)


def run_all(store: Store, settings: Settings, since_seq: int | None = None,
            rules: Sequence[CompiledRule] | None = None,
            detectors: Sequence[Detector] | None = None) -> RunResult:
    result = RunResult()
    if rules is None:
        rules, result.rule_report = load_rules(settings.detection.sigma_dirs)
    min_rank = LEVELS.index(settings.detection.sigma_min_level)
    rules = [r for r in rules if LEVELS.index(r.level) >= min_rank]

    found, result.errors = run_sigma(store, rules, since_seq, return_errors=True)
    heuristic: list[Detection] = []
    for det in default_detectors(settings) if detectors is None else detectors:
        try:
            heuristic += det.run(store, since_seq)
        except Exception as exc:  # a broken heuristic must not hide Sigma results
            log.exception("detector %s failed", det.rule_id)
            result.errors.append((det.rule_id, str(exc)))

    result.by_rule = dict(Counter(d.rule_title for d in [*found, *heuristic]))
    result.detections_new = store.insert_detections(found) + store.insert_detections(heuristic, replace=True)
    return result

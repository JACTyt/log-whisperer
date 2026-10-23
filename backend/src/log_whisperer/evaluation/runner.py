"""Run eval cases against one provider/model and write results."""

import json
import logging
import re
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from pydantic import BaseModel

from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.detection.sigma_rules import load_rules
from log_whisperer.evaluation.cases import EvalCase
from log_whisperer.evaluation.metrics import citation_metrics, key_fact_recall, technique_metrics
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import ingest_path
from log_whisperer.llm.base import LLMProvider
from log_whisperer.narrative.service import generate_narrative, load_incident_bundle
from log_whisperer.parsers import default_parsers, parser_by_type
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.store import Store

log = logging.getLogger(__name__)
METRICS = ["step_validity", "entity_grounding", "technique_precision", "technique_recall", "technique_f1",
           "key_fact_recall"]


class CaseResult(BaseModel):
    name: str
    skipped: str | None = None
    error: str | None = None
    incident_id: str | None = None
    metrics: dict[str, float] = {}
    predicted_techniques: list[str] = []
    rejected: int = 0


class EvalReport(BaseModel):
    provider: str
    model: str
    cases: list[CaseResult]
    aggregate: dict[str, float]


def _run_case(case: EvalCase, provider: LLMProvider, settings: Settings, root: Path, rules) -> CaseResult:
    res = CaseResult(name=case.name)
    paths = [root / f for f in case.files]
    if missing := [str(p) for p in paths if not p.exists()]:
        res.skipped = f"missing files: {', '.join(missing)}"
        return res
    with Store(":memory:") as store:
        parsers = [AuthLogParser(year=case.authlog_year) if p.source_type == "authlog" and case.authlog_year else p
                   for p in default_parsers()]
        force = next((p for p in parsers if p.source_type == case.parser), None) if case.parser else None
        if case.parser and force is None:
            force = parser_by_type(case.parser)
        for p in paths:
            ingest_path(store, p, parsers, force=force)
        run_all(store, settings, rules=rules)
        incidents = rebuild_incidents(store, settings)
        if not incidents:
            res.error = "no incident detected"
            return res
        target = max(incidents, key=lambda i: (len(i.detection_ids), len(i.context_event_ids)))
        res.incident_id = target.incident_id
        try:
            nv = generate_narrative(store, target.incident_id, provider, settings)
        except Exception as exc:  # one failing case must not stop the run
            res.error = f"{type(exc).__name__}: {exc}"
            return res
        bundle = load_incident_bundle(store, target.incident_id)
    predicted = {t for s in nv.steps for t in s.techniques}
    tm = technique_metrics(predicted, set(case.expected_techniques))
    res.predicted_techniques = sorted(predicted)
    res.rejected = len(nv.rejected)
    res.metrics = citation_metrics(nv) | {
        "technique_precision": tm["precision"], "technique_recall": tm["recall"], "technique_f1": tm["f1"],
        "key_fact_recall": key_fact_recall(nv, bundle.events_by_id, case.key_facts),
    }
    return res


def run_eval(cases: Sequence[EvalCase], provider: LLMProvider, settings: Settings, root: Path) -> EvalReport:
    rules, _ = load_rules(settings.detection.sigma_dirs)
    results = []
    for case in cases:
        log.info("eval case %s", case.name)
        results.append(_run_case(case, provider, settings, root, rules))
    scored = [r for r in results if r.metrics]
    aggregate = {m: sum(r.metrics[m] for r in scored) / len(scored) for m in METRICS} if scored else {}
    aggregate |= {"cases_scored": len(scored), "cases_skipped": sum(1 for r in results if r.skipped),
                  "cases_failed": sum(1 for r in results if r.error)}
    return EvalReport(provider=provider.name, model=provider.model, cases=results, aggregate=aggregate)


def write_report(report: EvalReport, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9.-]+", "_", f"{report.provider}-{report.model}")
    js = out_dir / f"{date.today():%Y-%m-%d}-{safe}.json"
    js.write_text(json.dumps(report.model_dump(), indent=2, default=str))
    md = out_dir / "SUMMARY.md"
    if not md.exists():
        md.write_text("| date | model | cases | step validity | entity grounding | ATT&CK P | ATT&CK R | "
                      "key facts |\n|---|---|---|---|---|---|---|---|\n")
    a = report.aggregate

    def pct(k: str) -> str:
        return f"{a[k] * 100:.0f}%" if k in a else "-"

    with md.open("a") as f:
        f.write(f"| {date.today():%Y-%m-%d} | {report.provider}:{report.model} | {int(a.get('cases_scored', 0))} | "
                f"{pct('step_validity')} | {pct('entity_grounding')} | {pct('technique_precision')} | "
                f"{pct('technique_recall')} | {pct('key_fact_recall')} |\n")
    return js, md

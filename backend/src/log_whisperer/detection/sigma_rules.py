"""Load Sigma rule files and compile them to SQL, reporting everything we skip."""

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from log_whisperer.detection.logsources import logsource_sql
from log_whisperer.detection.sigma_backend import compile_rule

log = logging.getLogger(__name__)

_TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)
LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    logsource_sql: str
    condition_sql: str
    path: Path


@dataclass
class RuleLoadReport:
    loaded: int = 0
    unsupported: list[tuple[str, str]] = field(default_factory=list)


def techniques_from_tags(tags: Iterable) -> list[str]:
    out = []
    for tag in tags:
        text = str(tag)
        if text.lower().startswith("attack."):
            name = text.split(".", 1)[1]
            if _TECHNIQUE.match(name):
                out.append(name.upper())
    return out


def _compile(rule: SigmaRule, path: Path) -> CompiledRule:
    ls_sql = logsource_sql(rule.logsource)
    if ls_sql is None:
        lsrc = rule.logsource
        raise NotImplementedError(
            f"unsupported logsource product={lsrc.product} category={lsrc.category} service={lsrc.service}"
        )
    return CompiledRule(
        rule_id=str(rule.id) if rule.id else rule.title,
        title=rule.title,
        level=rule.level.name.lower() if rule.level else "medium",
        techniques=techniques_from_tags(rule.tags or []),
        logsource_sql=ls_sql,
        condition_sql=compile_rule(rule),
        path=path,
    )


def load_rule_text(text: str, path: Path, statuses: set[str] | None, report: RuleLoadReport) -> list[CompiledRule]:
    """Compile every rule in one YAML document stream; failures go to the report."""
    out: list[CompiledRule] = []
    try:
        docs = [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as exc:
        report.unsupported.append((str(path), f"YAML error: {exc}"))
        return out
    items = []
    for doc in docs:
        if not isinstance(doc, dict):
            report.unsupported.append((str(path), "not a Sigma rule document"))
        elif "correlation" in doc:
            report.unsupported.append((f"{doc.get('title', '?')} ({path.name})", "correlation rules are not supported"))
        else:
            try:
                items += SigmaCollection.from_dicts([doc], collect_errors=True).rules
            except Exception as exc:
                report.unsupported.append((str(path), f"parse error: {exc}"))
    for item in items:
        name = f"{getattr(item, 'title', '?')} ({path.name})"
        if isinstance(item, SigmaCorrelationRule):
            report.unsupported.append((name, "correlation rules are not supported"))
            continue
        if not isinstance(item, SigmaRule):
            report.unsupported.append((name, f"unsupported item {type(item).__name__}"))
            continue
        if item.errors:
            report.unsupported.append((str(path), f"invalid rule: {item.errors[0]}"))
            continue
        status = item.status.name.lower() if item.status else "experimental"
        if statuses is not None and status not in statuses:
            report.unsupported.append((name, f"status {status} filtered"))
            continue
        try:
            out.append(_compile(item, path))
            report.loaded += 1
        except Exception as exc:
            report.unsupported.append((name, f"{type(exc).__name__}: {exc}"))
    return out


def load_rules(
    dirs: Sequence[Path], statuses: set[str] | None = frozenset({"stable", "test"})
) -> tuple[list[CompiledRule], RuleLoadReport]:
    report = RuleLoadReport()
    rules: list[CompiledRule] = []
    for d in dirs:
        d = Path(d)
        if not d.exists():
            report.unsupported.append((str(d), "rule directory not found"))
            continue
        for path in sorted([*d.rglob("*.yml"), *d.rglob("*.yaml")]):
            rules += load_rule_text(path.read_text(encoding="utf-8"), path, statuses, report)
    log.info("loaded %d sigma rules, %d unsupported", report.loaded, len(report.unsupported))
    return rules, report

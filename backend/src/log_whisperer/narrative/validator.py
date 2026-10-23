"""Deterministic citation validator: the trust boundary between model output and the UI (DESIGN §2, §10)."""

import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from log_whisperer.attack.catalog import Catalog
from log_whisperer.models import Event
from log_whisperer.narrative.prompt import RenderedContext
from log_whisperer.narrative.schema import CitedText, NarrativeStep, Rejection, ValidatedNarrative

TS_TOLERANCE = timedelta(seconds=60)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
MIN_ENTITY_LEN = 3


class ValidationContext:
    def __init__(self, rc: RenderedContext, events_by_id: Mapping[str, Event], known_entities: Iterable[str]):
        self.rc = rc
        self.events_by_id = events_by_id
        ents = {e.lower() for e in known_entities if e and len(e) >= MIN_ENTITY_LEN}
        self.entity_patterns = [(e, re.compile(rf"(?<![\w-]){re.escape(e)}(?![\w-])", re.I)) for e in sorted(ents)]

    def expand(self, aliases: list[str]) -> tuple[list[str], list[str], str | None]:
        """-> (event_ids, normalized aliases, error)"""
        ids, norm = [], []
        for a in aliases:
            alias = a.strip().strip("[]()").upper()
            if alias not in self.rc.alias_to_ids:
                return [], [], f"unknown_citation:{alias}"
            norm.append(alias)
            ids.extend(self.rc.alias_to_ids[alias])
        return list(dict.fromkeys(ids)), norm, None

    def haystack(self, event_ids: list[str]) -> str:
        parts = []
        for i in event_ids:
            e = self.events_by_id[i]
            parts += [str(v) for v in (e.host, e.user, e.src_ip, e.dst_ip, e.process, e.command_line) if v]
            parts += [e.raw, json.dumps(e.fields, default=str)]
        return "\n".join(parts).lower()

    def ungrounded(self, text: str, event_ids: list[str]) -> str | None:
        hay = self.haystack(event_ids)
        mentioned = [m.group(0) for rx in (IPV4, IPV6) for m in rx.finditer(text)]
        mentioned += [e for e, rx in self.entity_patterns if rx.search(text)]
        for ent in mentioned:
            if ent.lower() not in hay:
                return ent
        return None


def _parse_ts(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def check_cited(vc: ValidationContext, text: str, aliases: Any) -> tuple[list[str], list[str], str | None]:
    if not isinstance(aliases, list) or not aliases:
        return [], [], "no_citation"
    ids, norm, err = vc.expand([str(a) for a in aliases])
    if err:
        return [], [], err
    if ent := vc.ungrounded(text, ids):
        return [], [], f"ungrounded_entity:{ent}"
    return ids, norm, None


def validate(raw: dict[str, Any], rc: RenderedContext, events_by_id: Mapping[str, Event], catalog: Catalog,
             known_entities: Iterable[str]) -> ValidatedNarrative:
    vc = ValidationContext(rc, events_by_id, known_entities)
    out = ValidatedNarrative()

    summary = raw.get("summary") or {}
    s_text = str(summary.get("text", ""))
    ids, _, err = check_cited(vc, s_text, summary.get("event_ids"))
    if err:
        out.rejected.append(Rejection(index=-1, text=s_text, reason=err))
    else:
        out.summary = CitedText(text=s_text, event_ids=ids)

    for i, step in enumerate(raw.get("steps") or []):
        text = str(step.get("text", ""))
        ids, aliases, err = check_cited(vc, text, step.get("event_ids"))
        if err:
            out.rejected.append(Rejection(index=i, text=text, reason=err))
            continue
        ts = _parse_ts(str(step.get("ts", "")))
        lo = min(rc.alias_ts[a][0] for a in aliases) - TS_TOLERANCE
        hi = max(rc.alias_ts[a][1] for a in aliases) + TS_TOLERANCE
        if ts is None or not lo <= ts <= hi:
            out.rejected.append(Rejection(index=i, text=text, reason="timestamp_mismatch"))
            continue
        techniques = []
        for t in step.get("techniques") or []:
            tid = str(t).strip().upper()
            if catalog.is_valid(tid):
                techniques.append(catalog.resolve(tid))
            else:
                out.rejected.append(Rejection(index=i, text=text, reason=f"unknown_technique:{tid}"))
        out.steps.append(NarrativeStep(ts=ts, text=text, event_ids=ids, techniques=list(dict.fromkeys(techniques))))
    out.steps.sort(key=lambda s: s.ts)
    return out

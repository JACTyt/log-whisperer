"""Helpers shared by heuristic detectors."""

from collections.abc import Sequence
from datetime import timedelta

from log_whisperer.detection.base import uniq
from log_whisperer.ids import short_hash
from log_whisperer.models import Detection, Event
from log_whisperer.store import Store


def candidates(store: Store, where: str, params: list, since_seq: int | None,
               lookback: timedelta) -> list[Event]:
    """Events matching `where`; in incremental mode, only those near new events (with lookback)."""
    if since_seq is None:
        return store.query_events(where, params)
    first_new = store.sql(f"SELECT min(ts) FROM events WHERE ({where}) AND seq > ?", [*params, since_seq])[0][0]
    if first_new is None:
        return []
    return store.query_events(f"({where}) AND ts >= ?", [*params, first_new - lookback])


def has_new(events: Sequence[Event], since_seq: int | None) -> bool:
    return since_seq is None or any((e.seq or 0) > since_seq for e in events)


def make_detection(rule_id: str, title: str, severity: str, techniques: list[str],
                   events: Sequence[Event], key: str = "") -> Detection:
    """Detection id is anchored on the first event so a growing burst keeps its id."""
    events = sorted(events, key=lambda e: (e.ts, e.seq or 0))
    return Detection(
        detection_id=short_hash(rule_id, key, events[0].event_id),
        rule_id=rule_id,
        rule_title=title,
        rule_source="heuristic",
        severity=severity,
        techniques=techniques,
        event_ids=[e.event_id for e in events],
        ts_first=events[0].ts,
        ts_last=events[-1].ts,
        hosts=uniq(e.host for e in events),
        users=uniq(e.user for e in events),
        src_ips=uniq(e.src_ip for e in events),
    )

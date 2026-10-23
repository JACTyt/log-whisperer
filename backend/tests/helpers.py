"""Builders for synthetic events in tests."""

from datetime import datetime, timedelta
from itertools import count

from log_whisperer.models import Event

T0 = datetime(2026, 3, 14, 14, 0, 0)
_n = count()


def ev(minutes: float = 0, **kw) -> Event:
    i = next(_n)
    base = dict(
        ts=T0 + timedelta(minutes=minutes),
        source_type="authlog",
        channel="auth",
        host="web01",
        source_file="synthetic",
        record_ref=f"line:{i}",
        raw=f"synthetic event {i}",
        fields={},
    )
    return Event(**base | kw)


def failures(n: int, start: float = 0, step_sec: float = 10, **kw) -> list[Event]:
    kw = {"action": "ssh_auth", "outcome": "failure"} | kw
    return [ev(start + i * step_sec / 60, **kw) for i in range(n)]

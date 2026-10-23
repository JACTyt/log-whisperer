from datetime import datetime

import pytest

from log_whisperer.ids import make_event_id, normalize_user
from log_whisperer.models import Event


def test_event_id_deterministic():
    assert make_event_id("a.evtx", "record:1") == make_event_id("a.evtx", "record:1")
    assert len(make_event_id("a.evtx", "record:1")) == 16
    assert make_event_id("a.evtx", "record:1") != make_event_id("a.evtx", "record:2")
    assert make_event_id("a.evtx", "record:1") != make_event_id("b.evtx", "record:1")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CORP\\Bob", "bob"),
        ("bob@corp.local", "bob"),
        ("-", None),
        ("", None),
        ("  ", None),
        (None, None),
        ("Alice", "alice"),
        ("NT AUTHORITY\\SYSTEM", "system"),
    ],
)
def test_normalize_user(raw, expected):
    assert normalize_user(raw) == expected


def _event(**kw):
    base = dict(
        ts=datetime(2026, 1, 1),
        source_type="evtx",
        source_file="a.evtx",
        record_ref="record:1",
        raw="{}",
        fields={},
    )
    return Event(**base | kw)


def test_event_autofills_id():
    assert _event().event_id == make_event_id("a.evtx", "record:1")


def test_event_keeps_explicit_id():
    assert _event(event_id="abc").event_id == "abc"


def test_aware_ts_normalized_to_naive_utc():
    from datetime import timedelta, timezone

    e = _event(ts=datetime(2026, 1, 1, 16, 0, tzinfo=timezone(timedelta(hours=2))))
    assert e.ts == datetime(2026, 1, 1, 14, 0) and e.ts.tzinfo is None


def test_event_optional_columns_default_none():
    e = _event()
    assert e.host is None and e.user is None and e.seq is None and e.outcome is None

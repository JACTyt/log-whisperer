from datetime import datetime

from log_whisperer.models import Event
from log_whisperer.store import Store


def _event(n: int, **kw) -> Event:
    base = dict(
        ts=datetime(2026, 3, 14, 14, 0, n),
        source_type="authlog",
        channel="auth",
        host="web01",
        user="root",
        src_ip="203.0.113.7",
        action="ssh_auth",
        outcome="failure",
        source_file="/var/log/auth.log",
        record_ref=f"line:{n}",
        raw=f"line {n}",
        fields={"method": "password", "pid": n, "nested": {"a": [1, 2]}},
    )
    return Event(**base | kw)


def test_insert_and_get_roundtrip():
    with Store(":memory:") as s:
        e = _event(1)
        assert s.insert_events([e]) == 1
        got = s.get_event(e.event_id)
        assert got is not None
        assert got.model_dump(exclude={"seq"}) == e.model_dump(exclude={"seq"})


def test_get_missing_returns_none():
    with Store(":memory:") as s:
        assert s.get_event("nope") is None


def test_reinsert_is_idempotent():
    with Store(":memory:") as s:
        events = [_event(i) for i in range(5)]
        assert s.insert_events(events) == 5
        assert s.insert_events(events) == 0
        assert s.count_events() == 5


def test_duplicates_within_one_batch():
    with Store(":memory:") as s:
        assert s.insert_events([_event(1), _event(1)]) == 1


def test_seq_increases():
    with Store(":memory:") as s:
        assert s.max_seq() == 0
        s.insert_events([_event(i) for i in range(3)])
        assert s.max_seq() == 3
        assert s.get_event(_event(2).event_id).seq == 3


def test_large_batch_spans_chunks():
    with Store(":memory:") as s:
        assert s.insert_events(_event(i % 60, record_ref=f"line:{i}") for i in range(12_000)) == 12_000
        assert s.count_events() == 12_000


def test_file_db_persists(tmp_path):
    path = tmp_path / "sub" / "x.duckdb"
    with Store(path) as s:
        s.insert_events([_event(1)])
    with Store(path) as s:
        assert s.count_events() == 1

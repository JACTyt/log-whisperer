from pathlib import Path

import pytest

from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.incidents.context import select_context
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import ingest_path
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.store import Store
from tests.helpers import ev, failures

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path / "none.mmdb"
    return s


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_authlog_story_is_one_incident(store, settings):
    ingest_path(store, FIX / "auth.log", [], force=AuthLogParser(year=2026))
    run_all(store, settings)
    [inc] = rebuild_incidents(store, settings)
    assert inc.hosts == ["web01"] and "203.0.113.7" in inc.src_ips
    assert {"root", "backdoor"} <= set(inc.users)
    assert inc.severity == "high"
    assert {"T1110.001", "T1136.001"} <= set(inc.techniques)
    ctx = store.events_by_ids(inc.context_event_ids)
    # the sudo commands after the attack have no detection but are context
    assert any(e.action == "sudo" and "shadow" in (e.command_line or "") for e in ctx)
    assert store.get_incident(inc.incident_id) == inc
    assert [i.incident_id for i in rebuild_incidents(store, settings)] == [inc.incident_id]


def test_context_includes_cross_source_neighbours_and_excludes_unrelated(store, settings):
    store.insert_events(failures(12, src_ip="203.0.113.7", user="alice"))
    winlogon = ev(3, source_type="evtx", host="WS01", user="alice", action="logon", outcome="success")
    unrelated = ev(3, host="other", user="carol", action="sudo")
    store.insert_events([winlogon, unrelated])
    run_all(store, settings)
    [inc] = rebuild_incidents(store, settings)
    assert winlogon.event_id in inc.context_event_ids
    assert unrelated.event_id not in inc.context_event_ids


def test_context_cap_keeps_detection_events(store, settings):
    store.insert_events(failures(12, src_ip="203.0.113.7", user="alice"))
    store.insert_events([ev(1 + i / 100, user="alice", action="sudo") for i in range(50)])
    run_all(store, settings)
    [inc] = rebuild_incidents(store, settings)
    det_ids = {e for d in store.list_detections() for e in d.event_ids}
    ids = select_context(store, inc, store.list_detections(), neighbors=20, max_events=15)
    assert det_ids <= set(ids) and len(ids) == 15

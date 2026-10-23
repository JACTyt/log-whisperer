from pathlib import Path

import pytest

from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all, run_sigma
from log_whisperer.detection.sigma_rules import load_rules
from log_whisperer.ingest import ingest_path
from log_whisperer.parsers import default_parsers
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.store import Store

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture
def store():
    s = Store(":memory:")
    ingest_path(s, FIX / "auth.log", [], force=AuthLogParser(year=2026))
    ingest_path(s, FIX / "access.log", default_parsers())
    ingest_path(s, FIX / "winjson_flat.jsonl", default_parsers())
    yield s
    s.close()


def test_run_sigma_detections(store):
    rules, _ = load_rules([FIX / "rules"])
    dets = run_sigma(store, rules)
    by_rule = {}
    for d in dets:
        by_rule.setdefault(d.rule_title, []).append(d)
    assert len(by_rule["SSH Failed Password"]) == 12
    assert len(by_rule["SQL Injection Strings In URI"]) == 2
    assert len(by_rule["Encoded PowerShell"]) == 1
    ssh = by_rule["SSH Failed Password"][0]
    assert ssh.hosts == ["web01"] and ssh.src_ips == ["203.0.113.7"] and ssh.users == ["root"]
    assert ssh.techniques == ["T1110.001"] and ssh.severity == "low" and ssh.rule_source == "sigma"
    assert len(ssh.event_ids) == 1


def test_run_all_persists_and_is_idempotent(store):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    r1 = run_all(store, s, detectors=[])
    assert r1.detections_new == 15 and r1.by_rule["SSH Failed Password"] == 12
    assert r1.rule_report.loaded == 3
    r2 = run_all(store, s, detectors=[])
    assert r2.detections_new == 0
    assert len(store.list_detections()) == 15


def test_run_all_with_heuristics(store, tmp_path):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path / "missing.mmdb"
    r = run_all(store, s)
    assert r.by_rule["Brute-force authentication from 203.0.113.7"] == 1
    assert r.by_rule["New user added to admin group: backdoor → sudo"] == 1
    assert any(t.startswith("Suspicious PowerShell") for t in r.by_rule)
    assert r.detections_new == 18 and r.errors == []
    assert run_all(store, s).detections_new == 0


def test_since_seq_limits_to_new_events(store):
    rules, _ = load_rules([FIX / "rules"])
    assert run_sigma(store, rules, since_seq=store.max_seq()) == []


def test_min_level_filters(store):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.detection.sigma_min_level = "high"
    assert run_all(store, s, detectors=[]).detections_new == 3


def test_bad_rule_sql_is_reported_not_raised(store):
    rules, _ = load_rules([FIX / "rules"])
    rules[0].condition_sql = "this is not sql"
    _, errors = run_sigma(store, rules, return_errors=True)
    assert len(errors) == 1


def test_events_by_ids(store):
    dets = run_sigma(store, load_rules([FIX / "rules"])[0])
    events = store.events_by_ids(dets[0].event_ids + ["missing"])
    assert [e.event_id for e in events] == dets[0].event_ids

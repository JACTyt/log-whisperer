import json
from pathlib import Path

import pytest

from log_whisperer.attack import default_catalog
from log_whisperer.attack.table import attack_table
from log_whisperer.chat.service import MAX_TOOL_ROUNDS, ChatService
from log_whisperer.chat.tools import TOOLS, ChatScope
from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import ingest_path
from log_whisperer.llm.base import ChatTurn, ToolCall
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.narrative.schema import NarrativeStep, ValidatedNarrative
from log_whisperer.parsers import default_parsers
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.store import Store
from tests.helpers import ev

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path_factory.mktemp("g") / "none.mmdb"
    store = Store(":memory:")
    ingest_path(store, FIX / "auth.log", [], force=AuthLogParser(year=2026))
    ingest_path(store, FIX / "access.log", default_parsers())
    store.insert_events([ev(60 * 24 * 30, host="far-away", src_ip="203.0.113.7", action="ssh_auth", outcome="failure")])
    run_all(store, s)
    incs = rebuild_incidents(store, s)
    inc = max(incs, key=lambda i: len(i.context_event_ids))
    yield store, s, inc
    store.close()


def scope(env, kind="incident"):
    return ChatScope(kind=kind, incident=env[2] if kind == "incident" else None)


# -- ATT&CK table -------------------------------------------------------------------

def test_attack_table_orders_by_tactic(env):
    store, _, inc = env
    dets = store.list_detections(ids=inc.detection_ids)
    nv = ValidatedNarrative(steps=[NarrativeStep(ts=inc.ts_start, text="x", event_ids=["a"], techniques=["T1078"])])
    rows = attack_table(nv, dets, default_catalog())
    tactics = [r.tactic for r in rows]
    assert tactics.index("initial-access") < tactics.index("credential-access")
    t1078 = next(r for r in rows if r.technique_id == "T1078")
    assert t1078.step_indexes == [0] and t1078.name


# -- tools ----------------------------------------------------------------------------

def test_count_by_hosts_for_ip_scoped(env):
    store = env[0]
    r = TOOLS["count_by"].fn(store, scope(env), {"field": "host", "filter_field": "src_ip", "filter_value": "203.0.113.7"})
    hosts = {row["value"] for row in r.rows}
    assert "web01" in hosts and "far-away" not in hosts  # incident scope clamps time
    g = TOOLS["count_by"].fn(store, scope(env, "global"), {"field": "host", "filter_field": "src_ip",
                                                            "filter_value": "203.0.113.7"})
    assert "far-away" in {row["value"] for row in g.rows}
    assert all(row["sample_event_ids"] for row in r.rows)


def test_whitelist_rejects_unknown_columns(env):
    r = TOOLS["count_by"].fn(env[0], scope(env), {"field": "raw; DROP TABLE events"})
    assert r.error and "field must be one of" in r.error
    assert TOOLS["events_by_entity"].fn(env[0], scope(env), {"entity_type": "fields", "value": "x"}).error


def test_events_by_entity_and_search(env):
    store = env[0]
    r = TOOLS["events_by_entity"].fn(store, scope(env), {"entity_type": "user", "value": "BACKDOOR", "limit": 100})
    assert r.events and all(e.user == "backdoor" for e in r.events) and len(r.events) <= 50
    s = TOOLS["search_events"].fn(store, scope(env), {"text": "/etc/shadow", "limit": None})
    assert len(s.events) == 1
    assert TOOLS["search_events"].fn(store, scope(env), {"text": "100%_"}).events == []


def test_entity_summary(env):
    r = TOOLS["entity_summary"].fn(env[0], scope(env), {"entity_type": "src_ip", "value": "203.0.113.7"})
    assert {(row["action"], row["outcome"]) for row in r.rows} >= {("ssh_auth", "failure"), ("ssh_auth", "success")}


def test_incident_events_requires_incident(env):
    assert TOOLS["incident_events"].fn(env[0], scope(env, "global"), {}).error
    r = TOOLS["incident_events"].fn(env[0], scope(env), {"action": "sudo", "limit": None})
    assert r.events and all(e.action == "sudo" for e in r.events)


# -- chat service -----------------------------------------------------------------------

def _answer(items):
    return ChatTurn(content=json.dumps({"answer": items}))


def test_chat_cites_tool_results(env):
    store, s, inc = env
    fake = FakeProvider(chat_turns=[
        ChatTurn(content=None, tool_calls=[ToolCall("1", "count_by", {"field": "host", "filter_field": "src_ip",
                                                                      "filter_value": "203.0.113.7"})]),
        _answer([{"text": "203.0.113.7 touched web01.", "event_ids": ["E1"], "no_data": False},
                 {"text": "It also reached 10.9.9.9.", "event_ids": ["E1"], "no_data": False},
                 {"text": "Uncited claim.", "event_ids": [], "no_data": False}]),
    ])
    svc = ChatService(store, fake, s)
    session = svc.new_session(scope(env))
    ans = svc.ask(session, "Which hosts did 203.0.113.7 touch?")
    assert [x.text for x in ans.sentences] == ["203.0.113.7 touched web01."]
    assert {r.reason for r in ans.rejected} == {"ungrounded_entity:10.9.9.9", "no_citation"}
    assert ans.tool_calls[0].startswith("count_by(")
    tool_msg = next(m for m in session.messages if m.role == "tool")
    assert "examples: E1" in tool_msg.content
    assert inc.incident_id in session.messages[0].content


def test_chat_unknown_tool_and_no_data(env):
    store, s, _ = env
    fake = FakeProvider(chat_turns=[
        ChatTurn(content=None, tool_calls=[ToolCall("1", "drop_tables", {})]),
        _answer([{"text": "No matching events found.", "event_ids": [], "no_data": True}]),
    ])
    svc = ChatService(store, fake, s)
    session = svc.new_session(scope(env))
    ans = svc.ask(session, "Anything about mimikatz?")
    assert ans.no_data == ["No matching events found."] and ans.sentences == []
    assert "unknown tool" in next(m for m in session.messages if m.role == "tool").content


def test_chat_tool_loop_capped(env):
    store, s, _ = env
    looping = ChatTurn(content=None, tool_calls=[ToolCall("x", "search_events", {"text": "sshd"})])
    fake = FakeProvider(chat_turns=[looping] * MAX_TOOL_ROUNDS + [
        _answer([{"text": "Done.", "event_ids": [], "no_data": True}])])
    svc = ChatService(store, fake, s)
    session = svc.new_session(scope(env))
    ans = svc.ask(session, "loop")
    assert ans.no_data == ["Done."] and len(fake.calls) == MAX_TOOL_ROUNDS + 1
    assert any("Stop calling tools" in m.content for m in session.messages if m.role == "user")


def test_chat_followup_keeps_aliases(env):
    store, s, _ = env
    fake = FakeProvider(chat_turns=[
        ChatTurn(content=None, tool_calls=[ToolCall("1", "search_events", {"text": "/etc/shadow"})]),
        _answer([{"text": "backdoor read /etc/shadow.", "event_ids": ["E1"], "no_data": False}]),
        _answer([{"text": "That was via sudo as backdoor.", "event_ids": ["E1"], "no_data": False}]),
    ])
    svc = ChatService(store, fake, s)
    session = svc.new_session(scope(env))
    svc.ask(session, "Who read shadow?")
    assert len(svc.ask(session, "How?").sentences) == 1

from pathlib import Path

import pytest

from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import ingest_path
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.narrative.prompt import render_context
from log_whisperer.narrative.service import load_incident_bundle
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.report.markdown import cell, code_span
from log_whisperer.report.pdf import render_html
from log_whisperer.report.service import build_report
from log_whisperer.response.actions import ADVISORY, suggest_actions
from log_whisperer.rulegen.draft import draft_rule
from log_whisperer.store import Store

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path_factory.mktemp("g") / "none.mmdb"
    store = Store(":memory:")
    ingest_path(store, FIX / "auth.log", [], force=AuthLogParser(year=2026))
    run_all(store, s)
    [inc] = rebuild_incidents(store, s)
    bundle = load_incident_bundle(store, inc.incident_id)
    rc = render_context(bundle.incident, bundle.events, bundle.detections)
    yield store, s, inc, bundle, rc
    store.close()


def alias(env, pred):
    _, _, _, bundle, rc = env
    return next(a for a, ids in rc.alias_to_ids.items() if any(pred(bundle.events_by_id[i]) for i in ids))


# -- actions ---------------------------------------------------------------------------

def test_actions_validated(env):
    store, s, inc, _, _ = env
    ok = alias(env, lambda e: e.action == "ssh_auth" and e.outcome == "success" and e.src_ip == "203.0.113.7")
    created = alias(env, lambda e: e.action == "user_created")
    fake = FakeProvider([{"actions": [
        {"action": "Disable account backdoor", "rationale": "Created by the attacker.", "priority": "immediate",
         "event_ids": [created]},
        {"action": "Block 203.0.113.7 at the firewall", "rationale": "Source of the brute force.",
         "priority": "short_term", "event_ids": [ok]},
        {"action": "Block 198.51.100.1", "rationale": "Guess.", "priority": "immediate", "event_ids": [ok]},
        {"action": "Reimage", "rationale": "Uncited.", "priority": "long_term", "event_ids": []},
        {"action": "Panic", "rationale": "x", "priority": "yesterday", "event_ids": [ok]},
    ]}])
    acts, rejected = suggest_actions(store, inc.incident_id, fake, s)
    assert [a.priority for a in acts] == ["immediate", "short_term"]
    assert all(a.label == ADVISORY for a in acts)
    assert sorted(r.reason.split(":")[0] for r in rejected) == ["bad_priority", "no_citation", "ungrounded_entity"]


# -- rule drafts --------------------------------------------------------------------------

def _draft(env, tmp_path, yaml_text, cites):
    store, s, inc, _, _ = env
    fake = FakeProvider([{"yaml": yaml_text, "explanation": "test", "event_ids": cites}])
    return draft_rule(store, inc.incident_id, fake, s, tmp_path / "drafts")


GOOD = """title: Local user added to sudo group
id: not-a-uuid
status: stable
logsource: {product: linux, service: auth}
detection:
  keywords:
    - "to group 'sudo'"
  condition: keywords
level: high
tags: [attack.persistence, attack.t1098]
"""


def test_draft_accepted_and_saved(env, tmp_path):
    r = _draft(env, tmp_path, GOOD, [alias(env, lambda e: e.action == "group_member_added")])
    assert r.status == "accepted" and r.path.exists() and r.path.name.endswith("-1.yml")
    text = r.path.read_text()
    assert "status: experimental" in text and "log-whisperer draft" in text and "incident:" in text
    assert len(r.matched_event_ids) >= 1
    r2 = _draft(env, tmp_path, GOOD, [alias(env, lambda e: e.action == "group_member_added")])
    assert r2.path.name.endswith("-2.yml")


def test_draft_no_match_rejected(env, tmp_path):
    r = _draft(env, tmp_path, GOOD.replace("to group 'sudo'", "nothing like this"),
               [alias(env, lambda e: e.action == "group_member_added")])
    assert r.status == "rejected" and r.reason.startswith("no_match") and r.path is None


@pytest.mark.parametrize("text,reason", [
    ("title: [unclosed", "yaml_error"),
    ("title: a\n---\ntitle: b\n", "expected exactly one"),
    ("title: c\ncorrelation: {type: event_count}\n", "unsupported: correlation"),
    (GOOD.replace("product: linux, service: auth", "product: macos"), "unsupported"),
])
def test_draft_invalid(env, tmp_path, text, reason):
    r = _draft(env, tmp_path, text, [alias(env, lambda e: e.action == "group_member_added")])
    assert r.status == "rejected" and r.reason.startswith(reason)


def test_draft_unknown_citation(env, tmp_path):
    assert _draft(env, tmp_path, GOOD, ["E999"]).reason == "unknown_citation:E999"


# -- reports -------------------------------------------------------------------------------

def test_report_without_narrative(env):
    store, _, inc, _, _ = env
    md = build_report(store, inc.incident_id)
    assert "no narrative generated" in md and "## Timeline" in md and "Detection: " in md
    assert "[^e1]:" in md and "## MITRE ATT&CK" in md and "attack.mitre.org" in md


def test_report_escaping():
    assert cell("a|b <script>`x`") == "a\\|b &lt;script&gt;\\`x\\`"
    assert code_span("cmd `whoami` here") == "``cmd `whoami` here``"
    assert code_span("`edge`") == "`` `edge` ``"
    html = render_html("| a |\n|---|\n| " + cell("<img src=x onerror=alert(1)>") + " |")
    assert "<img" not in html and "&lt;img" in html


def test_report_with_narrative_and_actions(env):
    from log_whisperer.narrative.schema import CitedText, NarrativeStep, ValidatedNarrative
    from log_whisperer.response.actions import SuggestedAction

    store, _, inc, bundle, _ = env
    eid = bundle.events[0].event_id
    nv = ValidatedNarrative(summary=CitedText(text="Summary | with pipe", event_ids=[eid]),
                            steps=[NarrativeStep(ts=inc.ts_start, text="Step one", event_ids=[eid] * 5,
                                                 techniques=["T1110.001"])])
    store.save_narrative(inc.incident_id, "fake:model", nv)
    md = build_report(store, inc.incident_id, [SuggestedAction(action="Block IP", rationale="r", priority="immediate",
                                                               event_ids=[eid])])
    assert "Summary \\| with pipe" in md and "(+2 more)" in md and ADVISORY in md
    assert md.count(f"[^e1]:") == 1

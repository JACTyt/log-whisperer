import re
from datetime import datetime
from pathlib import Path

import pytest

from log_whisperer.config import Settings
from log_whisperer.evaluation.cases import EvalCase, KeyFact, load_cases
from log_whisperer.evaluation.metrics import citation_metrics, key_fact_recall, technique_metrics
from log_whisperer.evaluation.runner import run_eval, write_report
from log_whisperer.llm.base import LLMError
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.narrative.schema import NarrativeStep, Rejection, ValidatedNarrative
from tests.helpers import ev

FIX = Path(__file__).parents[1] / "fixtures"


def test_technique_metrics_partial_credit():
    m = technique_metrics({"T1110", "T1136.001"}, {"T1110.001", "T1136.001", "T1098"})
    assert m["precision"] == pytest.approx((0.5 + 1) / 2)
    assert m["recall"] == pytest.approx((0.5 + 1 + 0) / 3)
    assert technique_metrics(set(), set()) == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    assert technique_metrics(set(), {"T1078"})["f1"] == 0.0


def test_citation_metrics():
    nv = ValidatedNarrative(
        steps=[NarrativeStep(ts=datetime(2026, 1, 1), text="a", event_ids=["x"])],
        rejected=[Rejection(index=1, text="b", reason="ungrounded_entity:1.2.3.4"),
                  Rejection(index=0, text="a", reason="unknown_technique:T9999"),
                  Rejection(index=-1, text="s", reason="no_citation")],
    )
    m = citation_metrics(nv)
    assert m["step_validity"] == 0.5 and m["entity_grounding"] == 0.5
    assert citation_metrics(ValidatedNarrative()) == {"step_validity": 0.0, "entity_grounding": 0.0}


def test_key_fact_recall():
    e1 = ev(0, user="backdoor", action="user_created")
    e2 = ev(5, src_ip="203.0.113.7", action="ssh_auth", outcome="success")
    nv = ValidatedNarrative(steps=[NarrativeStep(ts=e1.ts, text="x", event_ids=[e1.event_id, e2.event_id])])
    by_id = {e1.event_id: e1, e2.event_id: e2}
    facts = [KeyFact(entity="backdoor", action="user_created"),
             KeyFact(entity="203.0.113.7", action="ssh_auth", outcome="success", approx_ts=e2.ts),
             KeyFact(entity="203.0.113.7", outcome="failure"),
             KeyFact(entity="backdoor", approx_ts=datetime(2030, 1, 1))]
    assert key_fact_recall(nv, by_id, facts) == 0.5
    assert key_fact_recall(ValidatedNarrative(), {}, []) == 1.0


def test_load_cases_normalizes_paths(tmp_path):
    d = tmp_path / "eval" / "cases"
    d.mkdir(parents=True)
    (d / "a.yaml").write_text("name: a\nfiles: ['backend\\\\tests\\\\fixtures\\\\auth.log']\n"
                              "expected_techniques: [T1110.001]\nkey_facts: [{entity: root}]\n")
    [case] = load_cases(d)
    assert case.files == [Path("backend/tests/fixtures/auth.log")] and case.key_facts[0].entity == "root"


def _settings(tmp_path):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path / "none.mmdb"
    return s


def _case(**kw):
    base = dict(name="ssh", files=[Path("auth.log")], authlog_year=2026,
                expected_techniques=["T1110.001", "T1136.001"],
                key_facts=[KeyFact(entity="backdoor", action="user_created")])
    return EvalCase(**base | kw)


class EchoProvider(FakeProvider):
    """Cites the first event of every rendered alias line so output is always valid."""

    def generate_json(self, system, user, schema):
        self.calls.append(("generate_json", user))
        lines = [ln for ln in user.splitlines() if re.match(r"^E\d+ ", ln)]
        steps = []
        for ln in lines:
            alias, rest = ln.split(" ", 1)
            ts = rest.split(" ")[0] if not rest.startswith("(") else rest.split(", ")[1].split(" ")[0]
            steps.append({"ts": ts, "text": "Activity observed.", "event_ids": [alias], "techniques": ["T1110.001"]})
        return {"summary": {"text": "Summary.", "event_ids": [lines[0].split(" ")[0]]}, "steps": steps}


def test_run_eval_end_to_end(tmp_path):
    report = run_eval([_case()], EchoProvider(), _settings(tmp_path), root=FIX)
    [r] = report.cases
    assert r.error is None and r.metrics["step_validity"] == 1.0
    assert r.metrics["key_fact_recall"] == 1.0 and r.metrics["technique_precision"] == 1.0
    assert 0 < r.metrics["technique_recall"] < 1
    assert report.aggregate["step_validity"] == 1.0
    js, md = write_report(report, tmp_path / "results")
    assert js.name.endswith("fake-fake-model.json") and "| fake:fake-model |" in md.read_text()


def test_missing_files_skipped_and_errors_isolated(tmp_path):
    cases = [_case(name="missing", files=[Path("nope/x.evtx")]), _case(name="boom"), _case(name="ok")]
    fake = EchoProvider()
    original = fake.generate_json
    calls = {"n": 0}

    def flaky(system, user, schema):
        calls["n"] += 1
        if calls["n"] <= 2:  # both attempts of the first case fail
            raise LLMError("provider down")
        return original(system, user, schema)

    fake.generate_json = flaky
    report = run_eval(cases, fake, _settings(tmp_path), root=FIX)
    status = {c.name: (c.skipped, c.error) for c in report.cases}
    assert status["missing"][0] and "provider down" in status["boom"][1] and status["ok"] == (None, None)
    assert report.aggregate["cases_scored"] == 1


def test_model_name_sanitized(tmp_path):
    report = run_eval([], FakeProvider(model="juilpark/gemma:q4"), _settings(tmp_path), root=FIX)
    js, _ = write_report(report, tmp_path)
    assert js.name.endswith("fake-juilpark_gemma_q4.json")
